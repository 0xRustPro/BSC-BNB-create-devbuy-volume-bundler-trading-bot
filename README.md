# BNB Chain Trading Bot

A trading bot for BNB Smart Chain that automates token deployment, liquidity management, and trading strategies on PancakeSwap and Four.meme.

## Features

- **Token Deployment** - Deploy ERC20 tokens with custom parameters
- **Liquidity Management** - Create and manage liquidity pools on PancakeSwap V3
- **Trading Strategies** - Sniper, bundler, and volume generation bots
- **Multi-Wallet Support** - Manage multiple wallets for distributed trading
- **MEV Protection** - Use bloXroute for atomic transaction bundling

## How It Works

### Sniper Bot
Monitors for new token launches and executes buy orders automatically.

### Volume Bot
Generates trading volume by executing small buy/sell transactions at intervals.

### Bundler Bot
Executes multiple transactions atomically for complex trading strategies.

## Quick Start

1. Install dependencies:
```bash
npm install
```

2. Configure your environment:
```bash
cp .env.example .env
# Edit .env with your RPC URL and private key
```

3. Run the bot:
```bash
node bundler.js
```

## Requirements

- Node.js v16+
- BNB Smart Chain RPC access
- Funded wallet with BNB
- bloXroute account (for MEV protection)

## Contract Details

- **Network**: BNB Smart Chain
- **Factory**: 0x5c952063c7fc8610FFDB798152D69F0B9550762b
- **Launch Cost**: ~0.005 BNB

## Security

⚠️ **Important**: This is for educational purposes only. Use at your own risk.

- Never commit private keys
- Test on testnet first
- Monitor gas fees
- Understand MEV risks

## Contact

Telegram: [@its0xopsdev](https://t.me/Rust0x_726)
