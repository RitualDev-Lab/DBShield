export interface PiiCategoryRule {
  category: string;
  columnRegex: RegExp;
  valueRegex?: RegExp;
  mask: (val: string) => string;
}

export const PII_RULES: PiiCategoryRule[] = [
  {
    category: "PASSWORD",
    columnRegex:
      /^(pass|passwd|password|password_hash|passwd_hash|pwd|salt|hash|secret|secret_key|private_key)$/i,
    mask: () => "[REDACTED_SECRET]",
  },
  {
    category: "AUTH_TOKEN",
    columnRegex:
      /^(token|auth_token|access_token|refresh_token|jwt|api_key|apikey|session_id|bearer)$/i,
    valueRegex:
      /(?:Bearer\s+[A-Za-z0-9\-._~+/]+=*|ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+|[a-zA-Z0-9_-]{32,64})/i,
    mask: () => "[REDACTED_TOKEN]",
  },
  {
    category: "EMAIL",
    columnRegex: /^(email|email_address|mail|user_email|contact_email)$/i,
    valueRegex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b/i,
    mask: (val: string) => {
      const atIdx = val.indexOf("@");
      if (atIdx <= 1) return "[REDACTED_EMAIL]";
      const firstChar = val[0];
      const domain = val.slice(atIdx);
      return `${firstChar}***${domain}`;
    },
  },
  {
    category: "PHONE",
    columnRegex: /^(phone|mobile|telephone|tel|cell|phone_number|mobile_no)$/i,
    valueRegex: /\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b/,
    mask: (val: string) => {
      const digits = val.replace(/\D/g, "");
      if (digits.length >= 4) {
        const last4 = digits.slice(-4);
        return `+***-***-${last4}`;
      }
      return "[REDACTED_PHONE]";
    },
  },
  {
    category: "CREDIT_CARD",
    columnRegex: /^(card|card_number|credit_card|cc_num|cvv|cvc|pan)$/i,
    valueRegex: /\b(?:\d{4}[- ]?){3}\d{4}\b/,
    mask: (val: string) => {
      const digits = val.replace(/\D/g, "");
      if (digits.length >= 4) {
        return `****-****-****-${digits.slice(-4)}`;
      }
      return "[REDACTED_CARD]";
    },
  },
  {
    category: "SSN_OR_NATIONAL_ID",
    columnRegex: /^(ssn|social_security|social_security_number|tax_id|national_id|aadhaar)$/i,
    valueRegex: /\b\d{3}-\d{2}-\d{4}\b/,
    mask: (val: string) => {
      const digits = val.replace(/\D/g, "");
      if (digits.length >= 4) {
        return `***-**-${digits.slice(-4)}`;
      }
      return "[REDACTED_ID]";
    },
  },
];
