import {
  Controller,
  Post,
  Get,
  Body,
  Query,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiQuery } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { WalletAuthService } from './wallet-auth.service';
import { ChallengeDto, VerifyDto, NonceQueryDto, VerifyWalletDto } from './dto/challenge.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly walletAuthService: WalletAuthService) {}

  /**
   * GET /api/auth/nonce?address=
   * Generate a cryptographically secure one-time nonce for a valid wallet address.
   * Stored in Redis with a 5-minute TTL.
   */
  @Get('nonce')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 20, ttl: 300_000 } })
  @ApiOperation({ summary: 'Request a wallet challenge nonce (GET)' })
  @ApiQuery({ name: 'address', description: 'Stellar Ed25519 wallet address (G...)' })
  @ApiResponse({
    status: 200,
    description: 'Nonce issued. Sign the message and POST to /auth/verify.',
  })
  async nonce(@Query() query: NonceQueryDto) {
    return this.walletAuthService.generateChallenge(query.address);
  }

  /**
   * POST /api/auth/challenge
   * Issue a domain-bound challenge nonce (legacy endpoint — kept for backwards compatibility).
   */
  @Post('challenge')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 20, ttl: 300_000 } })
  @ApiOperation({ summary: 'Request a wallet challenge nonce' })
  @ApiResponse({
    status: 200,
    description: 'Challenge issued. Sign the message and POST to /auth/verify.',
  })
  async challenge(@Body() dto: ChallengeDto) {
    return this.walletAuthService.generateChallenge(dto.publicKey);
  }

  /**
   * POST /api/auth/verify
   * Verify Ed25519 signature and issue a scoped JWT.
   * Accepts both { address, signature, nonce } and legacy { publicKey, nonce, signature }.
   * JWT: sub=walletAddress, walletAddress=walletAddress, scope=user — no admin capabilities.
   */
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 20, ttl: 300_000 } })
  @ApiOperation({ summary: 'Verify Ed25519 signature and obtain a JWT' })
  @ApiResponse({
    status: 200,
    description: 'JWT issued. sub=walletAddress, scope=user.',
  })
  async verify(@Body() dto: VerifyDto | VerifyWalletDto) {
    // Support both { address } (new) and { publicKey } (legacy) field names
    const address = (dto as VerifyWalletDto).address ?? (dto as VerifyDto).publicKey;
    return this.walletAuthService.verifyChallenge(address, dto.nonce, dto.signature);
  }
}
