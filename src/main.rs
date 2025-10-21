use ethers::prelude::*;
use ethers::abi::Abi;
use serde_json::Value;
use ethers::utils::parse_ether;
use ethers::types::U256;
use serde::{Deserialize, Serialize};
use dotenvy::from_filename;
use reqwest::{Client, multipart};
use std::path::Path;
use anyhow::Context;
use dotenv::dotenv;
use std::{env, fs, sync::Arc, str::FromStr};
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::from_str;
use ethers::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
struct CreateTokenRequest {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "shortName")]
    short_name: String,
    #[serde(rename = "desc")]
    desc: String,
    #[serde(rename = "imgUrl")]
    img_url: String,
    #[serde(rename = "launchTime")]
    launch_time: u64,
    #[serde(rename = "label")]
    label: String,
    #[serde(rename = "lpTradingFee")]
    lp_trading_fee: f64,
    #[serde(rename = "webUrl")]
    web_url: String,
    #[serde(rename = "twitterUrl")]
    twitter_url: String,
    #[serde(rename = "telegramUrl")]
    telegram_url: String,
    #[serde(rename = "preSale")]
    pre_sale: String,
    #[serde(rename = "onlyMPC")]
    only_mpc: bool,
    #[serde(rename = "raisedAmount")]
    raised_amount: u64, // must not be null
    #[serde(rename = "symbol")]
    symbol: String, // <-- required
    
}

#[derive(Deserialize, Debug)]
struct ApiResponse<T> {
    code: i32,
    message: Option<String>,
    data: Option<T>,
}

#[derive(Deserialize, Debug)]
struct CreateTokenResponse {
    token_id: Option<String>,
}
#[derive(Debug, Deserialize)]
struct UploadResponse {
    code: i32,
    data: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyInfo<'a> {
    address: &'a str,
    #[serde(rename = "networkCode")]
    network_code: &'a str,
    signature: String,
    #[serde(rename = "verifyType")]
    verify_type: &'a str,
}

#[derive(Debug, Serialize)]
struct LoginRequest<'a> {
    region: &'a str,
    #[serde(rename = "langType")]
    lang_type: &'a str,
    #[serde(rename = "loginIp")]
    login_ip: &'a str,
    #[serde(rename = "inviteCode")]
    invite_code: &'a str,
    #[serde(rename = "verifyInfo")]
    verify_info: VerifyInfo<'a>,
    #[serde(rename = "walletName")]
    wallet_name: &'a str,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    code: i32,
    data: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct NonceRequest<'a> {
    #[serde(rename = "accountAddress")]
    account_address: &'a str,

    #[serde(rename = "verifyType")]
    verify_type: &'a str,

    #[serde(rename = "networkCode")]
    network_code: &'a str,
}

#[derive(Debug, Deserialize)]
struct NonceResponse {
    code: i32,
    data: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok(); // loads .env
    let client = Client::new();
    let private_key = env::var("PRIVATE_KEY").context("Missing PRIVATE_KEY in .env")?;
    let wallet = private_key.parse::<LocalWallet>()?.with_chain_id(56u64);
    let address = wallet.address();

    // (You can use any public BSC endpoint)
    let provider = Provider::<Http>::try_from("https://bsc-dataseed.binance.org")?;

    // ✅ Get balance
    let balance = provider.get_balance(address, None).await?;

    // Convert from wei → BNB
    let balance_in_bnb = ethers::utils::format_units(balance, "ether")?;

    println!("Balance: {} BNB", balance_in_bnb);


    let address_str = format!("{:?}", address);
    let body = NonceRequest {
        account_address: &address_str,
        verify_type: "LOGIN",
        network_code: "BSC",
    };

    let res = client
        .post("https://four.meme/meme-api/v1/private/user/nonce/generate")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    if !res.status().is_success() {
        eprintln!("Request failed: {}", res.status());
        return Ok(());
    }

    let parsed: NonceResponse = res.json().await?;

    println!("Parsed: {:?}", parsed);

    if parsed.code == 0 {
        println!("✅ Nonce generated successfully!");
        println!("Nonce: {}", parsed.data);
    } else {
        eprintln!("❌ Failed to generate nonce: {:?}", parsed);
    }


    // Replace with your private key (for testing only, never hardcode in prod)
    
    
    let nonce = parsed.data; // normally you'd get this from the nonce API

    // The message to sign — must match exactly what the backend expects
    let message = format!("You are sign in Meme {}", nonce);
    let signature = wallet.sign_message(message).await?;
    let verify_info = VerifyInfo {
        address: &format!("{:?}", address),
        network_code: "BSC",
        signature: signature.to_string(),
        verify_type: "LOGIN",
    };

    let login_req = LoginRequest {
        region: "WEB",
        lang_type: "EN",
        login_ip: "",
        invite_code: "",
        verify_info,
        wallet_name: "MetaMask",
    };
    let client = Client::new();

    let res = client
        .post("https://four.meme/meme-api/v1/private/user/login/dex")
        .json(&login_req)
        .send()
        .await?;
    if !res.status().is_success() {
        eprintln!("❌ Login request failed: {}", res.status());
        return Ok(());
    }

    
    let parsed: LoginResponse = res.json().await?;
    println!("{:#?}", parsed);
    let access_token = if parsed.code == 0 {
        if let Some(token) = parsed.data {
            println!("✅ Login successful!");
            println!("Access token: {}", token);
            Some(token)
        } else {
            eprintln!("❌ No access token in response");
            None
        }
    } else {
        eprintln!("❌ Login failed: {:?}", parsed.message);
        None
    };
    
    let file_path = env::var("IMAGE_PATH").context("Missing IMAGE_PATH in .env")?;
    let path = Path::new(&file_path);
    // check if the file exists
    if !path.exists() {
        return Err(anyhow::anyhow!("File not found: {}", file_path));
    }

    let file_name = path
    .file_name()
    .and_then(|n| n.to_str())
    .context(format!("Invalid file path, could not extract filename: {}", file_path))?
    .to_string();

    // Read file bytes
    let file_bytes = tokio::fs::read(file_path).await?;

    // Create a multipart form with one "file" field
    let form = multipart::Form::new()
        .part(
            "file",
            multipart::Part::bytes(file_bytes)
                .file_name(file_name)
                .mime_str("image/png")?,
        );

    
        println!("Access token: --------------------------------");

        // Declare `res` outside so it's visible later
        let res = if let Some(token) = &access_token {
            let res = client
                .post("https://four.meme/meme-api/v1/private/token/upload")
                .header("meme-web-access", token)
                .multipart(form)
                .send()
                .await?;
        
            if !res.status().is_success() {
                eprintln!("❌ Upload failed: {}", res.status());
                return Ok(()); // early return on failure
            }
        
            res // return this `res` value from the if block
        } else {
            eprintln!("⚠️ Skipping upload — no access token");
            return Ok(()); // nothing to upload
        };
        
        // Parse the response JSON (res is still in scope here)
        let parsed: UploadResponse = res.json().await?;
        let uploaded_url = if parsed.code == 0 {
            if let Some(url) = parsed.data.clone() {
                println!("✅ Upload successful!");
                println!("🌐 Image URL: {}", url);
                url
            } else {
                eprintln!("⚠️ No URL returned from upload. Using fallback.");
                "https://fallback.url/default.png".to_string()
            }
        } else {
            eprintln!("❌ Upload error: {:?}", parsed.message);
            return Ok(()); // early return on failure
        };
    // Read config.json
    let data = fs::read_to_string("./src/config.json")?;
    let mut payload: CreateTokenRequest = from_str(&data)?;
    
    payload.img_url = uploaded_url.clone(); // inject new URL dynamically
    // Optional: log to verify
    println!("📤 Final payload:\n{}", serde_json::to_string_pretty(&payload)?);
    let res1 = if let Some(token) = &access_token {
        let res1 = client
            .post("https://four.meme/meme-api/v1/private/token/create")
            .header("Content-Type", "application/json")
            .header("meme-web-access", token)
            .json(&payload)
            .send()
            .await?;
        

        if !res1.status().is_success() {
            eprintln!("❌ Token creation failed: {}", res1.status());   // early return if the API call failed
        }
        //println!("{:#?}", res1);
        
        res1 // return this `res1` from the if block
    } else {
        eprintln!("⚠️ Skipping token creation — no access token");
        return Ok(()); // early return if token missing
    };
    let status = res1.status();
    let text = res1.text().await?;
    println!("📦 Raw response (status {}): {}", status, text);

    // Parse JSON
    // 👇 Clean and parse JSON
    let json_start = text.find('{').unwrap_or(0);
    let json_str = &text[json_start..];
    let json1: Value = serde_json::from_str(json_str)?;
    // Extract fields
    let create_arg_hex = json1["data"]["createArg"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let sign_hex = json1["data"]["signature"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    println!("🧩 createArg: {}", create_arg_hex);
    println!("🔏 signature: {}", sign_hex);

    // 1️⃣ Connect to BSC RPC
    let provider = Provider::<Http>::try_from("https://bsc-dataseed.binance.org")?;
    let provider = Arc::new(provider);

    // let wallet: LocalWallet = ""
    //     .parse::<LocalWallet>()?
    //     .with_chain_id(56u64); // BSC Mainnet = 56
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet));
    
    // 3️⃣ TokenManager2 contract address
    let token_manager_addr: Address = "0x5c952063c7fc8610FFDB798152D69F0B9550762b"
        .parse()
        .expect("invalid address");
     // 1️⃣ Read the ABI JSON file
    let abi_path = Path::new("abi/TokenManager2.lite.abi");
    let abi_json = fs::read_to_string(abi_path)?;
    let abi: Abi = serde_json::from_str(&abi_json)?;

    // 4️⃣ Initialize contract instance
    let contract = Contract::new(token_manager_addr, abi, client.clone());

    let create_arg_bytes = Bytes::from(hex::decode(create_arg_hex.trim_start_matches("0x"))?);
    let sign_bytes = Bytes::from(hex::decode(sign_hex.trim_start_matches("0x"))?);

    // 6️⃣ Call createToken
    // 👇 FIXED lifetime-safe call
    let deploy_fee = "0.01";
    let dev_buy_amount = payload.pre_sale;
    let value_in_wei: U256 = parse_ether(dev_buy_amount)?;
    let deploy_fee_wei: U256 = parse_ether(deploy_fee)?;
    // ✅ Add them
    let total_value_wei = value_in_wei + deploy_fee_wei;


    let call = contract.method::<_, H256>("createToken", (create_arg_bytes, sign_bytes))?.value(total_value_wei);
    let pending_tx = call.send().await?;

    println!("Transaction submitted: {:?}", pending_tx.tx_hash());
    Ok(())
}
