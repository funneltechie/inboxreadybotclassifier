export default {
  async fetch(request, env, ctx) {
    // 🔐 Authorization check via header
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
      
      // Get name data for enhanced analysis
      const firstName = (customData.firstName || body.firstName || "").trim();
      const lastName = (customData.lastName || body.lastName || "").trim();

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

      // --- Enhanced Detection Logic ---
      const localPart = inputEmail.split("@")[0];
      const domain = inputEmail.split("@")[1] || "";
      const entropy = calculateEntropy(localPart);
      const digitRatio = (localPart.replace(/[^0-9]/g, "").length / localPart.length) || 0;

      let reasons = [];
      let score = 0;

      // 1. Role-based emails (enhanced)
      const roleEmails = [
        "noreply", "no-reply", "info", "support", "admin", "contact",
        "webmaster", "postmaster", "newsletter", "mailer", "system", "alert",
        "notification", "automated", "bot", "service", "daemon"
      ];
      if (roleEmails.some(prefix => localPart.startsWith(prefix))) {
        reasons.push("Role-based email");
        score += 40;
      }

      // 2. Known spam/bot tools
      const spamTools = [
        "xrumer", "senuke", "gsa", "scrapebox", "xevil", "captchabreaker",
        "massmailer", "bulkmailer", "spambot", "autobot"
      ];
      if (spamTools.some(tool => localPart.includes(tool))) {
        reasons.push("Contains spam tool identifier");
        score += 60;
      }

      // 3. Enhanced entropy analysis (adjusted thresholds)
      const entropyResult = enhancedEntropyAnalysis(localPart);
      if (entropyResult.score > 0) {
        reasons.push(entropyResult.reason);
        score += entropyResult.score;
      }

      // 4. Improved digit analysis
      if (digitRatio > 0.4) {
        reasons.push("Very digit-heavy username");
        score += 25;
      } else if (digitRatio > 0.2) {
        reasons.push("Digit-heavy username");
        score += 15;
      }

      // 5. Sequential numbers detection
      if (/\d{2,}/.test(localPart)) {
        const numbers = localPart.match(/\d+/g);
        if (numbers && numbers.some(num => num.length >= 2)) {
          reasons.push("Contains sequential numbers");
          score += 20;
        }
      }

      // 6. Random character patterns
      if (/[a-z]{1,3}[A-Z]{1,3}[a-z]*/.test(localPart) || 
          /[a-zA-Z]+\d+[a-zA-Z]+\d+/.test(localPart)) {
        reasons.push("Random character pattern");
        score += 25;
      }

      // 7. Keyboard mashing detection
      const keyboardSequences = [
        'qwerty', 'asdf', 'zxcv', 'qazwsx', 'plmokn',
        'wert', 'erty', 'tyui', 'yuio', 'uiop',
        'sdfg', 'dfgh', 'fghj', 'ghjk', 'hjkl',
        'xcvb', 'cvbn', 'vbnm', 'mnbv', 'nbvc',
        'rtyu', 'tyu', 'yui', 'uio', 'iop',
        'fgh', 'ghj', 'hjk', 'jkl', 'kl'
      ];
      
      if (keyboardSequences.some(seq => localPart.includes(seq))) {
        reasons.push("Contains keyboard sequence");
        score += 35;
      }

      // 8. Enhanced consonant clusters
      const consonantResult = enhancedConsonantAnalysis(localPart);
      if (consonantResult.score > 0) {
        reasons.push(consonantResult.reason);
        score += consonantResult.score;
      }

      // 9. NEW: Random character email detection
      const randomEmailResult = analyzeEmailRandomness(localPart);
      if (randomEmailResult.score > 0) {
        reasons.push(randomEmailResult.reason);
        score += randomEmailResult.score;
      }

      // 10. Expanded disposable domains
      const disposableDomains = [
        // Original list
        "mailinator.com", "tempmail.com", "10minutemail.com",
        "guerrillamail.com", "yopmail.com",
        // Extended list
        "temp-mail.org", "throwaway.email", "maildrop.cc", "sharklasers.com",
        "guerrillamailblock.com", "pokemail.net", "spam4.me", "bccto.me",
        "chacuo.net", "dispostable.com", "fakeinbox.com", "hidemail.de",
        "mytrashmail.com", "no-spam.ws", "nospam.ze.tc", "nowmymail.com",
        "objectmail.com", "pookmail.com", "proxymail.eu", "rcpt.at",
        "safe-mail.net", "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
        "spamhole.com", "spamify.com", "spamthisplease.com", "tempail.com",
        "tempemail.com", "tempinbox.com", "tempmail.eu", "tempmailo.com",
        "tempmail2.com", "tempr.email", "trashmail.at", "trashmail.com",
        "trashmail.io", "trashmail.me", "trashmail.net", "wegwerfmail.de",
        "wegwerfmail.net", "wegwerfmail.org", "zehnminutenmail.de"
      ];
      
      if (disposableDomains.includes(domain)) {
        reasons.push("Disposable email domain");
        score += 50;
      }

      // 11. Suspicious domain patterns
      if (domain.includes("temp") || domain.includes("fake") || 
          domain.includes("spam") || domain.includes("trash") ||
          domain.includes("disposable") || domain.includes("throw")) {
        reasons.push("Suspicious domain keywords");
        score += 30;
      }

      // 12. Length analysis (refined)
      if (localPart.length > 25) {
        reasons.push("Extremely long local part");
        score += 20;
      } else if (localPart.length > 15) {
        reasons.push("Very long local part");
        score += 10;
      } else if (localPart.length < 3) {
        reasons.push("Suspiciously short local part");
        score += 15;
      }

      // 13. Enhanced name-based analysis
      if (firstName || lastName) {
        const nameScore = ultimateAnalyzeNames(firstName, lastName, localPart);
        if (nameScore.score > 0) {
          reasons.push(...nameScore.reasons);
          score += nameScore.score;
        }
      }

      // 14. Dot-separated bot patterns
      const dotPatternScore = analyzeDotPatterns(localPart);
      if (dotPatternScore.score > 0) {
        reasons.push(...dotPatternScore.reasons);
        score += dotPatternScore.score;
      }

      // 15. Common bot patterns
      const botPatterns = [
        /^[a-z]+\d+[a-z]*$/,  // letters + numbers + optional letters
        /^[a-z]{1,3}\d{4,}$/,  // few letters + many numbers
        /^test\d*$/,           // test + optional numbers
        /^user\d+$/,           // user + numbers
        /^[a-z]+_[a-z]+\d+$/   // word_word+numbers
      ];
      
      if (botPatterns.some(pattern => pattern.test(localPart))) {
        reasons.push("Matches common bot naming pattern");
        score += 25;
      }

      // --- Improved Scoring to Category (Lower Thresholds) ---
      let category = "Likely Human";
      if (score >= 70) category = "Very Likely Bot";
      else if (score >= 50) category = "Likely Automated";
      else if (score >= 30) category = "Suspicious";

      // --- FIXED: GHL API Request with Custom Field Lookup ---
      let ghlRes, ghlResponse, fieldId;
      
      try {
        // Step 1: Get the custom field ID for "contact.email_category"
        fieldId = await getCustomFieldId(ghlApiKey, "contact.email_category");
        
        if (!fieldId) {
          return new Response(JSON.stringify({
            success: false,
            message: "Custom field 'contact.email_category' not found in GoHighLevel",
            email: inputEmail,
            bot_score: score,
            category,
            reason_tags: reasons
          }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }

        // Step 2: Update contact using the actual field ID
        ghlRes = await fetch(`https://rest.gohighlevel.com/v1/contacts/${contactId}`, {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${ghlApiKey}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            customField: {
              [fieldId]: category
            }
          })
        });

        ghlResponse = await ghlRes.json();

      } catch (error) {
        return new Response(JSON.stringify({
          success: false,
          message: "Error updating GoHighLevel contact",
          error: error.message,
          email: inputEmail,
          bot_score: score,
          category,
          reason_tags: reasons
        }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(JSON.stringify({
        success: true,
        email: inputEmail,
        bot_score: score,
        category,
        reason_tags: reasons,
        contactId,
        fieldId,
        ghlUpdated: ghlRes.ok,
        ghlResponse,
        debug: {
          entropy: entropy.toFixed(2),
          digitRatio: (digitRatio * 100).toFixed(1) + "%",
          localPartLength: localPart.length,
          domain: domain,
          dotCount: (localPart.match(/\./g) || []).length
        }
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

// 🔍 Helper: Get custom field ID by name
async function getCustomFieldId(apiKey, fieldName) {
  try {
    const response = await fetch("https://rest.gohighlevel.com/v1/custom-fields/", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch custom fields: ${response.status}`);
    }

    const data = await response.json();
    
    // Look for the field by name
    const field = data.customFields?.find(f => 
      f.fieldKey === fieldName || 
      f.name === fieldName ||
      f.fieldKey === fieldName.replace("contact.", "")
    );

    return field?.id || null;

  } catch (error) {
    console.error("Error fetching custom field ID:", error);
    return null;
  }
}

// 🔢 Helper: entropy calculator (unchanged)
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

// 🔴 Helper: NEW - Enhanced entropy analysis with dynamic thresholds
function enhancedEntropyAnalysis(localPart) {
  const entropy = calculateEntropy(localPart);
  const length = localPart.length;
  
  // Dynamic thresholds based on string length
  let baseThreshold = 3.2;
  if (length <= 10) baseThreshold = 2.8;
  if (length <= 8) baseThreshold = 2.5;
  if (length <= 6) baseThreshold = 2.2;
  
  if (entropy > baseThreshold + 1.0) {
    return { score: 35, reason: "Very high entropy for string length" };
  } else if (entropy > baseThreshold + 0.5) {
    return { score: 25, reason: "High entropy for string length" };
  } else if (entropy > baseThreshold) {
    return { score: 15, reason: "Moderate entropy for string length" };
  }
  
  return { score: 0, reason: null };
}

// 🔴 Helper: NEW - Enhanced consonant cluster analysis
function enhancedConsonantAnalysis(localPart) {
  // Find all consonant clusters
  const consonantClusters = localPart.match(/[bcdfghjklmnpqrstvwxyz]{2,}/gi) || [];
  const totalClusterLength = consonantClusters.reduce((sum, cluster) => sum + cluster.length, 0);
  const longestCluster = Math.max(...consonantClusters.map(c => c.length), 0);
  
  if (longestCluster >= 4) {
    return { score: 20, reason: "Contains long consonant clusters" };
  } else if (totalClusterLength >= 6) {
    return { score: 15, reason: "Multiple consonant clusters" };
  } else if (consonantClusters.length >= 3) {
    return { score: 10, reason: "Many consonant clusters" };
  }
  
  return { score: 0, reason: null };
}

// 🔴 Helper: NEW - Random character email detection
function analyzeEmailRandomness(localPart) {
  // Skip if too short or has obvious patterns
  if (localPart.length < 6) return { score: 0, reason: null };
  
  // Check for recognizable patterns that suggest non-randomness
  const hasRecognizablePattern = 
    /^[a-z]+\d+$/.test(localPart) ||  // name+numbers
    /^[a-z]+\.[a-z]+$/.test(localPart) ||  // name.name
    /^[a-z]+_[a-z]+$/.test(localPart) ||  // name_name
    /^(test|user|admin|info|mail|email|contact)/.test(localPart) ||  // common prefixes
    localPart.includes('mail') || localPart.includes('email');  // email-related
  
  if (hasRecognizablePattern) {
    return { score: 0, reason: null };
  }
  
  // Check for randomness indicators
  const vowels = (localPart.match(/[aeiou]/g) || []).length;
  const consonants = (localPart.match(/[bcdfghjklmnpqrstvwxyz]/g) || []).length;
  const vowelRatio = vowels / localPart.length;
  
  // Very low vowel ratio suggests randomness
  if (vowelRatio < 0.2 && consonants >= 6) {
    return { score: 25, reason: "Random character email address" };
  }
  
  // Check for lack of common letter patterns
  const hasCommonPatterns = 
    /ing|tion|er|ed|ly|th|he|an|re|nd|on|en|at|ou|it|is|or|ti|as|to|io/.test(localPart);
  
  if (!hasCommonPatterns && localPart.length >= 8) {
    return { score: 20, reason: "No recognizable patterns in email" };
  }
  
  return { score: 0, reason: null };
}

// 🧑 Helper: ULTIMATE enhanced name analysis
function ultimateAnalyzeNames(firstName, lastName, localPart) {
  let score = 0;
  let reasons = [];

  // Check for domain extensions in names
  const domainExtensions = /\.(com|org|net|ru|de|uk|fr|it|es|pl|br|jp|cn|in|au|ca|io|co|me|tv|cc|biz|info|name|pro|mobi|tel|travel|museum|aero|coop|jobs|mil|edu|gov|int|arpa)$/i;
  if (domainExtensions.test(firstName) || domainExtensions.test(lastName)) {
    reasons.push("Names contain domain extensions");
    score += 40;
  }

  // Check for website-like patterns
  const websitePattern = /^[a-z0-9-]+\.[a-z]{2,4}$/i;
  if (websitePattern.test(firstName) || websitePattern.test(lastName)) {
    reasons.push("Names look like websites");
    score += 35;
  }

  // Check for URL-like patterns
  if (firstName.includes("www.") || lastName.includes("www.") ||
      firstName.includes("http") || lastName.includes("http")) {
    reasons.push("Names contain URL patterns");
    score += 45;
  }

  // NEW: Check for mixed case suffixes (major bot indicator)
  const mixedCaseSuffixResult = analyzeMixedCaseSuffix(firstName, lastName);
  if (mixedCaseSuffixResult.score > 0) {
    reasons.push(mixedCaseSuffixResult.reason);
    score += mixedCaseSuffixResult.score;
  }

  // NEW: Check for unnatural name construction
  const nameConstructionResult = analyzeNameConstruction(firstName, lastName);
  if (nameConstructionResult.score > 0) {
    reasons.push(nameConstructionResult.reason);
    score += nameConstructionResult.score;
  }

  // Check for random character suffixes in names
  const randomSuffixes = /[A-Z]{2,}[a-z]*[A-Z]+/;
  if (randomSuffixes.test(firstName) || randomSuffixes.test(lastName)) {
    reasons.push("Names contain random character patterns");
    score += 40;
  }

  // Check for repeated patterns
  if (firstName && lastName && firstName.toLowerCase() === lastName.toLowerCase().substring(0, firstName.length)) {
    reasons.push("First name repeated in last name");
    score += 30;
  }

  // Check for very short or very long names
  if ((firstName && firstName.length < 2) || (lastName && lastName.length < 2)) {
    reasons.push("Suspiciously short names");
    score += 20;
  }

  if ((firstName && firstName.length > 15) || (lastName && lastName.length > 20)) {
    reasons.push("Unusually long names");
    score += 15;
  }

  // Check for numbers in names
  if (/\d/.test(firstName) || /\d/.test(lastName)) {
    reasons.push("Names contain numbers");
    score += 35;
  }

  // Check for special characters in names
  if (/[^a-zA-Z\s\-\.]/.test(firstName) || /[^a-zA-Z\s\-\.]/.test(lastName)) {
    reasons.push("Names contain special characters");
    score += 25;
  }

  // Check for common bot name patterns
  const botNamePatterns = [
    /^[a-z]+\d+$/i,  // name + numbers
    /^test/i,        // starts with test
    /^user/i,        // starts with user
    /^bot/i,         // starts with bot
    /^fake/i,        // starts with fake
    /^admin/i,       // starts with admin
    /^guest/i        // starts with guest
  ];

  if (botNamePatterns.some(pattern => pattern.test(firstName) || pattern.test(lastName))) {
    reasons.push("Names match bot patterns");
    score += 30;
  }

  // Check for keyboard sequences in names
  const keyboardSequences = ['qwerty', 'asdf', 'zxcv', 'qazwsx'];
  if (keyboardSequences.some(seq => 
    firstName.toLowerCase().includes(seq) || lastName.toLowerCase().includes(seq))) {
    reasons.push("Names contain keyboard sequences");
    score += 35;
  }

  return { score, reasons };
}

// 🔴 Helper: NEW - Mixed case suffix detection
function analyzeMixedCaseSuffix(firstName, lastName) {
  // Pattern: lowercase letters followed by 2+ uppercase letters
  const mixedCasePattern = /[a-z]+[A-Z]{2,}$/;
  
  if (mixedCasePattern.test(firstName) || mixedCasePattern.test(lastName)) {
    return { score: 30, reason: "Mixed case suffix in names" };
  }
  
  // Alternative pattern: ends with single uppercase letters
  const singleUpperPattern = /[a-z]+[A-Z]+$/;
  if (singleUpperPattern.test(firstName) || singleUpperPattern.test(lastName)) {
    return { score: 20, reason: "Uppercase suffix in names" };
  }
  
  return { score: 0, reason: null };
}

// 🔴 Helper: NEW - Unnatural name construction detection
function analyzeNameConstruction(firstName, lastName) {
  // Common first names that bots often use as base
  const commonFirstNames = [
    'john', 'james', 'robert', 'michael', 'william', 'david', 'richard', 
    'charles', 'joseph', 'thomas', 'christopher', 'daniel', 'paul', 'mark',
    'donald', 'george', 'kenneth', 'steven', 'edward', 'brian', 'ronald',
    'anthony', 'kevin', 'jason', 'matthew', 'gary', 'timothy', 'jose',
    'larry', 'jeffrey', 'frank', 'scott', 'eric', 'stephen', 'andrew',
    'mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara',
    'susan', 'jessica', 'sarah', 'karen', 'nancy', 'lisa', 'betty',
    'helen', 'sandra', 'donna', 'carol', 'ruth', 'sharon', 'michelle',
    'laura', 'sarah', 'kimberly', 'deborah', 'dorothy', 'lisa', 'nancy'
  ];
  
  const firstNameLower = firstName.toLowerCase();
  const lastNameLower = lastName.toLowerCase();
  
  // Check if starts with common name but has unusual suffix
  const firstNameHasCommonBase = commonFirstNames.some(name => 
    firstNameLower.startsWith(name) && firstNameLower.length > name.length + 2
  );
  
  const lastNameHasCommonBase = commonFirstNames.some(name => 
    lastNameLower.startsWith(name) && lastNameLower.length > name.length + 2
  );
  
  if (firstNameHasCommonBase || lastNameHasCommonBase) {
    return { score: 25, reason: "Unnatural name construction pattern" };
  }
  
  // Check for names that look like they were generated (common name + random suffix)
  const hasGeneratedPattern = 
    /^[a-z]+[a-z]{4,}$/i.test(firstName) && firstName.length > 10 ||
    /^[a-z]+[a-z]{4,}$/i.test(lastName) && lastName.length > 12;
  
  if (hasGeneratedPattern) {
    return { score: 15, reason: "Generated name pattern" };
  }
  
  return { score: 0, reason: null };
}

// 🔴 Helper: Dot-separated patterns (unchanged)
function analyzeDotPatterns(localPart) {
  let score = 0;
  let reasons = [];

  // Skip analysis if no dots present
  if (!localPart.includes('.')) {
    return { score, reasons };
  }

  const segments = localPart.split('.');
  const dotCount = segments.length - 1;

  // 1. Excessive dots detection
  if (dotCount >= 4) {
    reasons.push("Excessive dots in email");
    score += 30;
  } else if (dotCount >= 3) {
    reasons.push("Many dots in email");
    score += 15;
  }

  // 2. Single character segments
  const singleCharSegments = segments.filter(seg => seg.length === 1).length;
  if (singleCharSegments >= 3) {
    reasons.push("Multiple single character segments");
    score += 30;
  } else if (singleCharSegments >= 2) {
    reasons.push("Single character segments");
    score += 20;
  }

  // 3. Numbers after dots
  if (/\.\d+/.test(localPart)) {
    reasons.push("Numbers after dots");
    score += 20;
  }

  // 4. Very short segments (average length)
  const avgSegmentLength = segments.reduce((sum, seg) => sum + seg.length, 0) / segments.length;
  if (segments.length >= 4 && avgSegmentLength < 2.5) {
    reasons.push("Artificially fragmented structure");
    score += 25;
  }

  // 5. Unnatural segmentation patterns
  const hasVeryShortSegments = segments.some(seg => seg.length === 1);
  const hasNumberSegments = segments.some(seg => /^\d+$/.test(seg));
  const tooManySegments = segments.length > 4;

  if (hasVeryShortSegments && (hasNumberSegments || tooManySegments)) {
    reasons.push("Unnatural email segmentation");
    score += 20;
  }

  // 6. Consecutive dots or empty segments
  if (localPart.includes('..') || segments.some(seg => seg.length === 0)) {
    reasons.push("Invalid dot placement");
    score += 25;
  }

  // 7. Pattern suggesting word splitting
  const withoutDots = localPart.replace(/\./g, '');
  if (segments.length >= 3 && withoutDots.length >= 6 && 
      segments.every(seg => seg.length <= 4) && 
      !/\d/.test(withoutDots.substring(0, withoutDots.length - 3))) {
    reasons.push("Possible word fragmentation");
    score += 15;
  }

  return { score, reasons };
}
