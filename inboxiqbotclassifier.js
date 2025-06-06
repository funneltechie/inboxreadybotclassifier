export default {
  async fetch(request, env, ctx) {
    try {
      const data = await request.json();
      const email = data.inputEmail?.toLowerCase() || "";
      const contactId = data.contactId;
      const ghlApiKey = data.apiKey;

      if (!email || !contactId || !ghlApiKey) {
        return new Response(
          JSON.stringify({ error: "Missing required parameters." }),
          { status: 400 }
        );
      }

      // --- Core Detection Logic ---
      const localPart = email.split("@")[0];
      const domain = email.split("@")[1] || "";
      const entropy = calculateEntropy(localPart);
      const digitRatio = (localPart.replace(/[^0-9]/g, "").length / localPart.length) || 0;

      let reasons = [];
      let score = 0;

      // Role-based patterns
      const roleEmails = ["noreply", "info", "support", "admin", "contact", "webmaster", "postmaster", "newsletter", "mailer", "system"];
      if (roleEmails.some(prefix => localPart.startsWith(prefix))) {
        reasons.push("Role-based email");
        score += 30;
      }

      // High entropy detection
      if (entropy > 3.5) {
        reasons.push("High entropy local part");
        score += 25;
      }

      // Numeric-heavy
      if (digitRatio > 0.3) {
        reasons.push("Digit-heavy username");
        score += 15;
      }

      // Known disposable domains
      const disposableDomains = ["mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com"];
      if (disposableDomains.includes(domain)) {
        reasons.push("Disposable domain");
        score += 30;
      }

      // Length or randomness
      if (localPart.length > 20 || localPart.length < 3) {
        reasons.push("Suspicious length");
        score += 10;
      }

      // Assign category
      let category = "Likely Human";
      if (score >= 81) category = "Very Likely Bot";
      else if (score >= 61) category = "Likely Automated";
      else if (score >= 41) category = "Suspicious";

      // --- Update GHL ---
      const ghlRes = await fetch(`https://rest.gohighlevel.com/v1/contacts/${contactId}`, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${ghlApiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          customField: [
            {
              key: "contact.email_category",
              value: category,
            },
          ],
        }),
      });

      const ghlResponse = await ghlRes.json();

      return new Response(
        JSON.stringify({
          email,
          bot_score: score,
          category,
          reason_tags: reasons,
          contactId,
          ghlUpdated: ghlRes.ok,
          ghlResponse,
        }),
        { status: 200 }
      );
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500 });
    }
  },
};

// --- Entropy Calculation Helper ---
function calculateEntropy(str) {
  const map = {};
  for (const char of str) {
    map[char] = (map[char] || 0) + 1;
  }
  const len = str.length;
  return -Object.values(map).reduce((acc, n) => {
    const p = n / len;
    return acc + p * Math.log2(p);
  }, 0);
}

