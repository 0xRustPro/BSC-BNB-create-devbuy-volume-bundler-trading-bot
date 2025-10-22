# BNB Four.meme Trading Bot

BNB chain advanced automated trading bot for Four.meme platform on BSC (Binance Smart Chain) with multiple features for token creation, buying, and volume generation on BNB, BSC chain.

## Features

### 1. Token Creation & Dev Buy
- Creates new tokens on Four.meme platform
- Authenticates with Four.meme API using wallet signature
- Uploads token image and metadata
- Executes initial dev buy transaction

### 2. Bundle Buy (Multi-Wallet Trading)
- Coordinate purchases across multiple wallets simultaneously
- Distribute buy amounts across different wallet addresses
- Increase token liquidity and trading volume
- Configurable wallet lists and buy amounts per wallet

### 3. High Volume Trading (Buy & Sell Loops)
- Automated buy and sell cycles to generate high token volume
- Configurable trading intervals and amounts
- Random timing variations to appear more natural
- Volume boosting for token listing and market attention

## Setup

1. **Install Rust** (if not already installed)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Create `.env` file** in project root:
   ```env
   # Main wallet for token creation
   PRIVATE_KEY=your_main_wallet_private_key
   IMAGE_PATH=./path/to/your/token/image.png
   
   # For bundle buying (multiple wallets)
   BUNDLE_WALLETS=wallet1_key,wallet2_key,wallet3_key,wallet4_key
   BUNDLE_AMOUNTS=0.001,0.002,0.0015,0.003
   
   # For volume trading
   VOLUME_LOOPS=10
   BUY_AMOUNT=0.01
   SELL_PERCENTAGE=0.95
   TRADING_INTERVAL=30
   ```

3. **Configure token** in `src/config.json`:
   ```json
   {
     "name": "YourTokenName",
     "shortName": "SYMBOL",
     "desc": "Token description",
     "symbol": "BNB",
     "preSale": "0.00001"
   }
   ```

## Usage

### Token Creation Only
```bash
cargo run -- --mode create
```

### Bundle Buy (Multi-Wallet)
```bash
cargo run -- --mode bundle --token-address 0x...
```

### Volume Trading (Buy/Sell Loops)
```bash
cargo run -- --mode volume --token-address 0x... --loops 20
```

### Combined Operations
```bash
cargo run -- --mode create-bundle-volume
```

## Configuration Options

### Environment Variables (.env)
- `PRIVATE_KEY`: Main wallet private key for token creation
- `IMAGE_PATH`: Local path to token image file
- `BUNDLE_WALLETS`: Comma-separated private keys for bundle buying
- `BUNDLE_AMOUNTS`: Comma-separated BNB amounts for each bundle wallet
- `VOLUME_LOOPS`: Number of buy/sell cycles to execute
- `BUY_AMOUNT`: BNB amount for each buy transaction
- `SELL_PERCENTAGE`: Percentage of holdings to sell (0.95 = 95%)
- `TRADING_INTERVAL`: Seconds between trades in volume mode

### Token Configuration (config.json)
- `name`: Full token name
- `shortName`: Token symbol
- `preSale`: Initial buy amount in BNB
- `desc`: Token description
- `launchTime`: Unix timestamp (future date)
- `lpTradingFee`: Liquidity pool trading fee percentage

## Workflow Examples

### 1. Create Token + Bundle Buy
```
1. Create token with main wallet (0.011 BNB required)
2. Wait for token contract deployment
3. Execute bundle buys across multiple wallets
4. Generate initial volume and liquidity
```

### 2. Volume Trading Session
```
1. Start with existing token address
2. Execute 10-20 buy/sell cycles over time
3. Random intervals (30-60 seconds between trades)
4. Maintain 5% holdings at all times
5. Create natural-looking trading patterns
```

### 3. Full Launch Strategy
```
1. Token creation with dev buy
2. Bundle buy across 4-6 wallets (0.002-0.005 BNB each)
3. Wait 2-3 minutes for initial setup
4. Begin volume trading loops for 30-60 minutes
5. Monitor and adjust trading parameters
```

## Requirements

### Minimum BNB Balances
- **Main Wallet**: 0.011+ BNB (creation + dev buy)
- **Bundle Wallets**: 0.002-0.01 BNB each (depending on strategy)
- **Volume Trading**: Additional 0.1+ BNB for trading loops

### Additional Requirements
- **Local Image File**: PNG/JPG for token (not URL)
- **Multiple Wallets**: For bundle buying features
- **Stable Internet**: For consistent API and blockchain interaction

## Advanced Features

### Smart Timing
- Random delays between transactions
- Natural trading patterns
- Anti-MEV protection

### Risk Management
- Maximum loss limits per wallet
- Emergency stop conditions
- Transaction failure retry logic

### Monitoring
- Real-time balance tracking
- Transaction success/failure logging
- Volume and price impact analysis

## Troubleshooting

**"insufficient funds"**: Check BNB balance across all configured wallets

**"File not found"**: Set `IMAGE_PATH` to local file path, not URL

**"Bundle buy failed"**: Verify wallet private keys and amounts in environment

**"Volume trading stopped"**: Check wallet balances and token address validity

## Security

⚠️ **Critical Security Notes**:
- Never commit `.env` files with private keys
- Use separate wallets for different functions
- Test with small amounts first
- Monitor all transactions carefully
- Keep backup of wallet private keys securely

Developer: [@Manokil](https://t.me/Rust0x_726)
