export default {
  async fetch(request, env, ctx) {
    // 🔐 Authorization header check
    const authHeader = request.headers.get("x-api-key");
    if (authHeader !== env.HUMANIQ_SECRET) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 403,
        headers: { "Content-Type": "application/json" }
      });
    }

    try {
      const body = await request.json();
      const { customData = {} } = body;

      const inputEmail = (customData.inputEmail || body.inputEmail || "").toLowerCase();
      const contactId = customData.contactId || body.contactId;
      const ghlApiKey = customData.apiKey || body.apiKey || env.GHL_SUBACCOUNT_API_KEY;

      // 🛑 Basic validation
      if (!contactId || !ghlApiKey) {
        return new Response(JSON.stringify({
          success: false,
          message: "Missing required fields",
          debug: body
        }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      if (!inputEmail || inputEmail.trim() === "") {
        return new Response(JSON.stringify({
          success: true,
          message: "No email provided — skipping classification"
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      // --- Detection Logic ---
      const localPart = inputEmail.split("@")[0];
      const domain = inputEmail.split("@")[1] || "";
      const entropy = calculateEntropy(localPart);
      const digitRatio = (localPart.replace(/[^0-9]/g, "").length / localPart.length) || 0;

      let reasons = [];
      let score = 0;

      const roleEmails = [
        "noreply", "no-reply", "info", "support", "admin", "contact",
        "webmaster", "postmaster", "newsletter", "mailer", "system", "alert"
      ];
      if (roleEmails.some(prefix => localPart.startsWith(prefix))) {
        reasons.push("Role-based email");
        score += 30;
      }

      if (entropy > 3.5) {
        reasons.push("High entropy local part");
        score += 25;
      }

      if (digitRatio > 0.3) {
        reasons.push("Digit-heavy username");
        score += 15;
      }

      const disposableDomains = [
        "mailinator.com", "tempmail.com", "10minutemail.com",
        "guerrillamail.com", "yopmail.com"
      ];
      if (disposableDomains.includes(domain)) {
        reasons.push("Disposable domain");
        score += 30;
      }

      if (localPart.length > 20 || localPart.length < 3) {
        reasons.push("Suspicious local part length");
        score += 10;
      }

      // --- Classification ---
      let category = "Likely Human";
      if (score >= 81) category = "Very Likely Bot";
      else if (score >= 61) category = "Likely Automated";
      else if (score >= 41) category = "Suspicious";

      // --- Update GHL Contact Field ---
      const ghlRes = await fetch(`https://rest.gohighlevel.com/v1/contacts/${contactId}`, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${ghlApiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          customField: [
            {
              key: "contact.email_category",
              value: category
            }
          ]
        })
      });

      const ghlResponse = await ghlRes.json();

      // ✅ Final Response
      return new Response(JSON.stringify({
        success: true,
        email: inputEmail,
        bot_score: score,
        category,
        reason_tags: reasons,
        contactId,
        ghlUpdated: ghlRes.ok,
        ghlResponse
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });

    } catch (err) {
      return new Response(JSON.stringify({
        success: false,
        message: "Error processing request",
        error: err.message
      }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }
};

// 🔢 Entropy calculator helper
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

