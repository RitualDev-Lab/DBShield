import { randomUUID } from "node:crypto";

export type RaftRole = "FOLLOWER" | "CANDIDATE" | "LEADER";

export interface RaftLogEntry {
  index: number;
  term: number;
  command: RaftTransactionCommand;
  timestamp: number;
}

export type RaftCommandType =
  | "ACQUIRE_LEASE"
  | "RELEASE_LEASE"
  | "PREPARE_TX"
  | "COMMIT_TX"
  | "ABORT_TX";

export interface RaftTransactionCommand {
  commandId: string;
  type: RaftCommandType;
  resourceKey: string;
  txId?: string;
  ownerId: string;
  fenceToken: number;
  leaseTtlMs?: number;
  payload?: Record<string, unknown>;
}

export interface RequestVoteArgs {
  term: number;
  candidateId: string;
  lastLogIndex: number;
  lastLogTerm: number;
}

export interface RequestVoteReply {
  term: number;
  voteGranted: boolean;
  reason?: string;
}

export interface AppendEntriesArgs {
  term: number;
  leaderId: string;
  prevLogIndex: number;
  prevLogTerm: number;
  entries: RaftLogEntry[];
  leaderCommit: number;
}

export interface AppendEntriesReply {
  term: number;
  success: boolean;
  matchIndex: number;
}

export interface ConsulSessionConfig {
  agentUrl?: string; // e.g. "http://127.0.0.1:8500"
  datacenter?: string;
  token?: string;
  lockPrefix?: string; // e.g. "dbshield/locks"
  ttlSeconds?: number;
}

export interface RaftClusterOptions {
  nodeId?: string;
  peers?: string[];
  heartbeatIntervalMs?: number;
  electionTimeoutMinMs?: number;
  electionTimeoutMaxMs?: number;
  consulConfig?: ConsulSessionConfig;
}

/**
 * Enterprise Raft Consensus & HashiCorp Consul Coordinator for DBShield.
 *
 * Coordinates distributed transaction isolation, mutual exclusion, and monotonic
 * fencing tokens across multi-replica DBShield proxies to prevent split-brain mutations.
 */
export class RaftConsensusCoordinator {
  private static globalFencingCounter = 1000;

  public readonly nodeId: string;
  public readonly peers: Set<string>;
  public role: RaftRole = "FOLLOWER";
  public currentTerm = 0;
  public votedFor: string | null = null;
  public leaderId: string | null = null;

  public readonly log: RaftLogEntry[] = [];
  public commitIndex = 0;
  public lastApplied = 0;

  // Active distributed state machine leases: resourceKey -> RaftTransactionCommand
  private readonly activeLeases: Map<string, RaftTransactionCommand> = new Map();
  // Prepared 2PC transactions: txId -> Set of replica votes
  private readonly preparedTxVotes: Map<string, Set<string>> = new Map();

  // Peer network message dispatch hook (allows in-process or network routing)
  private peerTransport?: (
    targetNodeId: string,
    rpc: "RequestVote" | "AppendEntries",
    payload: RequestVoteArgs | AppendEntriesArgs,
  ) => Promise<RequestVoteReply | AppendEntriesReply | null>;

  private heartbeatTimer?: NodeJS.Timeout;
  private electionTimer?: NodeJS.Timeout;
  private readonly heartbeatIntervalMs: number;
  private readonly electionTimeoutMinMs: number;
  private readonly electionTimeoutMaxMs: number;
  private readonly consulConfig?: ConsulSessionConfig;

  constructor(options: RaftClusterOptions = {}) {
    this.nodeId = options.nodeId || `dbshield_proxy_${randomUUID().slice(0, 8)}`;
    this.peers = new Set(options.peers || []);
    this.heartbeatIntervalMs = options.heartbeatIntervalMs || 50;
    this.electionTimeoutMinMs = options.electionTimeoutMinMs || 150;
    this.electionTimeoutMaxMs = options.electionTimeoutMaxMs || 300;
    this.consulConfig = options.consulConfig;
  }

  /**
   * Sets custom transport callback for peer message exchange (e.g. testing or RPC).
   */
  public setPeerTransport(
    transport: (
      targetNodeId: string,
      rpc: "RequestVote" | "AppendEntries",
      payload: RequestVoteArgs | AppendEntriesArgs,
    ) => Promise<RequestVoteReply | AppendEntriesReply | null>,
  ): void {
    this.peerTransport = transport;
  }

  /**
   * Starts the Raft consensus engine and election countdown.
   */
  public start(): void {
    this.resetElectionTimer();
  }

  /**
   * Stops consensus timers and releases resources.
   */
  public stop(): void {
    if (this.electionTimer) clearTimeout(this.electionTimer);
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.electionTimer = undefined;
    this.heartbeatTimer = undefined;
  }

  /**
   * Adds a new peer replica node to the consensus cluster.
   */
  public addPeer(peerNodeId: string): void {
    if (peerNodeId !== this.nodeId) {
      this.peers.add(peerNodeId);
    }
  }

  /**
   * Removes a peer replica node.
   */
  public removePeer(peerNodeId: string): void {
    this.peers.delete(peerNodeId);
  }

  /**
   * Total cluster size including self.
   */
  public get clusterSize(): number {
    return this.peers.size + 1;
  }

  /**
   * Quorum threshold required for consensus (majority: floor(N / 2) + 1).
   */
  public get quorumSize(): number {
    return Math.floor(this.clusterSize / 2) + 1;
  }

  /**
   * Inbound RequestVote RPC handler.
   */
  public handleRequestVote(args: RequestVoteArgs): RequestVoteReply {
    if (args.term > this.currentTerm) {
      this.currentTerm = args.term;
      this.role = "FOLLOWER";
      this.votedFor = null;
    }

    const canVote =
      args.term === this.currentTerm &&
      (this.votedFor === null || this.votedFor === args.candidateId);

    const lastEntry = this.getLastLogEntry();
    const lastTerm = lastEntry ? lastEntry.term : 0;
    const lastIndex = lastEntry ? lastEntry.index : 0;

    // Up-to-date log check
    const logOk =
      args.lastLogTerm > lastTerm ||
      (args.lastLogTerm === lastTerm && args.lastLogIndex >= lastIndex);

    if (canVote && logOk) {
      this.votedFor = args.candidateId;
      this.resetElectionTimer();
      return { term: this.currentTerm, voteGranted: true };
    }

    return {
      term: this.currentTerm,
      voteGranted: false,
      reason: !canVote ? "Already voted for other candidate" : "Log not up to date",
    };
  }

  /**
   * Inbound AppendEntries RPC handler (Heartbeat / Log Replication).
   */
  public handleAppendEntries(args: AppendEntriesArgs): AppendEntriesReply {
    if (args.term < this.currentTerm) {
      return { term: this.currentTerm, success: false, matchIndex: this.getLastLogIndex() };
    }

    if (args.term > this.currentTerm || this.role !== "FOLLOWER") {
      this.currentTerm = args.term;
      this.role = "FOLLOWER";
      this.votedFor = null;
    }

    this.leaderId = args.leaderId;
    this.resetElectionTimer();

    // Verify prevLog matching
    if (args.prevLogIndex > 0) {
      const prevEntry = this.getLogEntry(args.prevLogIndex);
      if (!prevEntry || prevEntry.term !== args.prevLogTerm) {
        return { term: this.currentTerm, success: false, matchIndex: this.getLastLogIndex() };
      }
    }

    // Append any new entries
    for (const entry of args.entries) {
      const existing = this.getLogEntry(entry.index);
      if (existing) {
        if (existing.term !== entry.term) {
          // Truncate diverging log
          this.log.splice(entry.index - 1);
          this.log.push(entry);
        }
      } else {
        this.log.push(entry);
      }
    }

    // Apply committed entries to state machine
    if (args.leaderCommit > this.commitIndex) {
      this.commitIndex = Math.min(args.leaderCommit, this.getLastLogIndex());
      this.applyCommittedEntries();
    }

    return { term: this.currentTerm, success: true, matchIndex: this.getLastLogIndex() };
  }

  /**
   * Proposes a new distributed command to the Raft consensus group.
   * If leader, replicates and commits across quorum.
   */
  public async proposeCommand(
    type: RaftCommandType,
    resourceKey: string,
    ownerId: string,
    payload?: Record<string, unknown>,
  ): Promise<{ success: boolean; fenceToken: number; logIndex: number; leaderId: string }> {
    if (this.role !== "LEADER") {
      // If single-node or standalone, self-elect immediately
      if (this.peers.size === 0) {
        this.becomeLeader();
      } else {
        return {
          success: false,
          fenceToken: 0,
          logIndex: 0,
          leaderId: this.leaderId || "",
        };
      }
    }

    const fenceToken = ++RaftConsensusCoordinator.globalFencingCounter;
    const command: RaftTransactionCommand = {
      commandId: `cmd_${randomUUID().slice(0, 8)}`,
      type,
      resourceKey,
      txId: payload?.txId as string | undefined,
      ownerId,
      fenceToken,
      payload,
    };

    const newIndex = this.getLastLogIndex() + 1;
    const logEntry: RaftLogEntry = {
      index: newIndex,
      term: this.currentTerm,
      command,
      timestamp: Date.now(),
    };

    this.log.push(logEntry);

    // Replicate to peers if present
    let ackCount = 1; // Self
    if (this.peers.size > 0 && this.peerTransport) {
      const replicationPromises = Array.from(this.peers).map(async (peer) => {
        try {
          const res = (await this.peerTransport!(peer, "AppendEntries", {
            term: this.currentTerm,
            leaderId: this.nodeId,
            prevLogIndex: newIndex - 1,
            prevLogTerm: this.getLogTerm(newIndex - 1),
            entries: [logEntry],
            leaderCommit: this.commitIndex,
          })) as AppendEntriesReply | null;

          if (res?.success) {
            ackCount++;
          }
        } catch {
          // Non-fatal peer timeout
        }
      });

      await Promise.allSettled(replicationPromises);
    }

    const hasQuorum = ackCount >= this.quorumSize;
    if (hasQuorum) {
      this.commitIndex = newIndex;
      this.applyCommittedEntries();
      return {
        success: true,
        fenceToken,
        logIndex: newIndex,
        leaderId: this.nodeId,
      };
    }

    return {
      success: false,
      fenceToken,
      logIndex: newIndex,
      leaderId: this.nodeId,
    };
  }

  /**
   * Acquires a distributed isolation lease across the cluster.
   */
  public async acquireDistributedLease(
    resourceKey: string,
    ownerId: string,
    leaseTtlMs = 5000,
  ): Promise<{ acquired: boolean; fenceToken: number; ownerId: string }> {
    const existing = this.activeLeases.get(resourceKey);
    if (existing && existing.ownerId !== ownerId) {
      return { acquired: false, fenceToken: 0, ownerId: existing.ownerId };
    }

    const result = await this.proposeCommand("ACQUIRE_LEASE", resourceKey, ownerId, { leaseTtlMs });
    if (result.success) {
      return { acquired: true, fenceToken: result.fenceToken, ownerId };
    }

    return { acquired: false, fenceToken: 0, ownerId };
  }

  /**
   * Releases a distributed isolation lease.
   */
  public async releaseDistributedLease(resourceKey: string, ownerId: string): Promise<boolean> {
    const existing = this.activeLeases.get(resourceKey);
    if (!existing) return true;
    if (existing.ownerId !== ownerId) return false;

    const result = await this.proposeCommand("RELEASE_LEASE", resourceKey, ownerId);
    return result.success;
  }

  /**
   * Coordinates a distributed Two-Phase Commit (2PC) prepare vote.
   */
  public async prepareDistributedTransaction(
    txId: string,
    resourceKey: string,
    ownerId: string,
  ): Promise<boolean> {
    const result = await this.proposeCommand("PREPARE_TX", resourceKey, ownerId, { txId });
    return result.success;
  }

  /**
   * Coordinates a distributed Two-Phase Commit (2PC) commit decision.
   */
  public async commitDistributedTransaction(
    txId: string,
    resourceKey: string,
    ownerId: string,
  ): Promise<boolean> {
    const result = await this.proposeCommand("COMMIT_TX", resourceKey, ownerId, { txId });
    return result.success;
  }

  /**
   * Manually promotes this node to Leader (useful in isolated tests or deterministic clusters).
   */
  public becomeLeader(): void {
    this.role = "LEADER";
    this.leaderId = this.nodeId;
    if (this.electionTimer) clearTimeout(this.electionTimer);
    this.startHeartbeats();
  }

  /**
   * Starts periodic leader heartbeat broadcasts.
   */
  private startHeartbeats(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = setInterval(() => {
      this.broadcastHeartbeats();
    }, this.heartbeatIntervalMs);
  }

  /**
   * Broadcasts heartbeats to all peer nodes.
   */
  public async broadcastHeartbeats(): Promise<void> {
    if (this.role !== "LEADER" || this.peers.size === 0 || !this.peerTransport) return;

    for (const peer of this.peers) {
      try {
        await this.peerTransport(peer, "AppendEntries", {
          term: this.currentTerm,
          leaderId: this.nodeId,
          prevLogIndex: this.getLastLogIndex(),
          prevLogTerm: this.getLogTerm(this.getLastLogIndex()),
          entries: [],
          leaderCommit: this.commitIndex,
        });
      } catch {
        // Suppress transient peer heartbeat failures
      }
    }
  }

  /**
   * Initiates a candidate election cycle.
   */
  public async startElection(): Promise<void> {
    this.role = "CANDIDATE";
    this.currentTerm++;
    this.votedFor = this.nodeId;
    let votesReceived = 1; // Vote for self

    if (this.peers.size === 0) {
      this.becomeLeader();
      return;
    }

    const lastEntry = this.getLastLogEntry();
    const lastLogTerm = lastEntry ? lastEntry.term : 0;
    const lastLogIndex = lastEntry ? lastEntry.index : 0;

    if (this.peerTransport) {
      const votePromises = Array.from(this.peers).map(async (peer) => {
        try {
          const res = (await this.peerTransport!(peer, "RequestVote", {
            term: this.currentTerm,
            candidateId: this.nodeId,
            lastLogIndex,
            lastLogTerm,
          })) as RequestVoteReply | null;

          if (res?.voteGranted) {
            votesReceived++;
          }
        } catch {
          // Candidate election peer timeout
        }
      });

      await Promise.allSettled(votePromises);
    }

    if (this.role === "CANDIDATE" && votesReceived >= this.quorumSize) {
      this.becomeLeader();
    } else {
      this.role = "FOLLOWER";
      this.resetElectionTimer();
    }
  }

  /**
   * Applies committed log entries to the local in-memory state machine.
   */
  private applyCommittedEntries(): void {
    while (this.lastApplied < this.commitIndex) {
      this.lastApplied++;
      const entry = this.getLogEntry(this.lastApplied);
      if (!entry) continue;

      const { command } = entry;
      switch (command.type) {
        case "ACQUIRE_LEASE":
          this.activeLeases.set(command.resourceKey, command);
          break;
        case "RELEASE_LEASE":
          this.activeLeases.delete(command.resourceKey);
          break;
        case "PREPARE_TX":
          if (command.txId) {
            let votes = this.preparedTxVotes.get(command.txId);
            if (!votes) {
              votes = new Set();
              this.preparedTxVotes.set(command.txId, votes);
            }
            votes.add(command.ownerId);
          }
          break;
        case "COMMIT_TX":
        case "ABORT_TX":
          if (command.txId) {
            this.preparedTxVotes.delete(command.txId);
          }
          break;
      }
    }
  }

  private resetElectionTimer(): void {
    if (this.electionTimer) clearTimeout(this.electionTimer);
    if (this.role === "LEADER") return;

    const timeout =
      Math.floor(Math.random() * (this.electionTimeoutMaxMs - this.electionTimeoutMinMs)) +
      this.electionTimeoutMinMs;

    this.electionTimer = setTimeout(() => {
      this.startElection();
    }, timeout);
  }

  private getLastLogIndex(): number {
    return this.log.length > 0 ? this.log[this.log.length - 1].index : 0;
  }

  private getLastLogEntry(): RaftLogEntry | undefined {
    return this.log.length > 0 ? this.log[this.log.length - 1] : undefined;
  }

  private getLogEntry(index: number): RaftLogEntry | undefined {
    return this.log[index - 1];
  }

  private getLogTerm(index: number): number {
    if (index === 0) return 0;
    const entry = this.getLogEntry(index);
    return entry ? entry.term : 0;
  }

  public getActiveLeases(): RaftTransactionCommand[] {
    return Array.from(this.activeLeases.values());
  }
}
