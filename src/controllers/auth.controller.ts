import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  UseGuards, 
  Req, 
  HttpCode, 
  HttpStatus,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from '../services/auth.service';
import { UserService } from '../services/user.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { OAuthAccountDto, SignUpDto, SignInDto, SetPasswordDto, ChangePasswordDto } from '../dto/auth.dto';
import { OAuthProvider } from '../schemas/user.schema';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private authService: AuthService,
    private userService: UserService,
  ) {}



  /**
   * Health check endpoint
   * GET /auth/health
   */
  @Get('health')
  @ApiOperation({ summary: 'Health check endpoint' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  getHealth() {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'auth-service',
    };
  }

  /**
   * User registration with email and password
   * POST /auth/signup
   */
  @Post('signup')
  @ApiOperation({ summary: 'User registration with email and password' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Body() signUpData: SignUpDto) {
    try {
      const result = await this.authService.signUp(signUpData);
      
      this.logger.log(`New user registered: ${signUpData.email}`);
      return result;
    } catch (error) {
      this.logger.error(`Sign up error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * User login with email/username and password
   * POST /auth/signin
   */
  @Post('signin')
  @ApiOperation({ summary: 'User login with email/username and password' })
  @ApiResponse({ status: 200, description: 'User signed in successfully' })
  @HttpCode(HttpStatus.OK)
  async signIn(@Body() signInData: SignInDto) {
    try {
      const result = await this.authService.signIn(signInData);
      
      this.logger.log(`User signed in: ${signInData.emailOrUsername}`);
      return result;
    } catch (error) {
      this.logger.error(`Sign in error: ${error.message}`, error.stack);
      throw error;
    }
  }



  /**
   * Sync NextAuth.js session with backend auth service
   * POST /auth/sync
   */
  @Post('sync')
  @ApiOperation({ summary: 'Sync NextAuth.js session with backend auth service' })
  @ApiResponse({ status: 200, description: 'Session synced successfully' })
  @HttpCode(HttpStatus.OK)
  async syncSession(@Body() sessionData: {
    providerId: string;
    email: string;
    name: string;
    profilePicture?: string;
    provider: string;
    accessToken?: string;
    refreshToken?: string;
  }) {
    try {
      this.logger.log(`Received sync request with data: ${JSON.stringify(sessionData)}`);
      
      if (!sessionData.email) {
        throw new BadRequestException('User email is required');
      }

      if (!sessionData.provider) {
        throw new BadRequestException('Provider is required');
      }

      const oauthProvider = sessionData.provider === 'github' ? OAuthProvider.GITHUB : OAuthProvider.GOOGLE;

      // Create OAuth account data
      const oauthAccount: OAuthAccountDto = {
        provider: oauthProvider,
        providerId: sessionData.providerId,
        email: sessionData.email,
        accessToken: sessionData.accessToken,
        refreshToken: sessionData.refreshToken,
      };

      // Look for existing user by email first
      let user = await this.userService.findByEmail(sessionData.email);

      if (user) {
        // Update OAuth account info
        user = await this.userService.addOAuthAccount(user._id.toString(), oauthAccount);
        this.logger.log(`Synced existing user: ${user.email}`);
      } else {
        // Create new user
        user = await this.userService.createUser({
          email: sessionData.email,
          name: sessionData.name,
          profilePicture: sessionData.profilePicture,
          oauthAccount,
        });
        this.logger.log(`Created new user via sync: ${user.email}`);
      }

      // Generate JWT tokens for our auth system
      const tokens = await this.authService.generateTokens(user);

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          id: user._id.toString(),
          email: user.email,
          name: user.name,
          profilePicture: user.profilePicture,
          lastLogin: user.lastLogin,
        },
      };
    } catch (error) {
      this.logger.error(`Session sync error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Set password for OAuth users
   * POST /auth/set-password
   */
  @Post('set-password')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Set password for OAuth users' })
  @ApiResponse({ status: 200, description: 'Password set successfully' })
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async setPassword(@Req() req: Request, @Body() setPasswordData: SetPasswordDto) {
    try {
      const user = req.user as any;
      
      if (setPasswordData.password !== setPasswordData.confirmPassword) {
        throw new BadRequestException('Passwords do not match');
      }

      const result = await this.authService.setPassword(user.userId, setPasswordData.password);
      
      this.logger.log(`Password set for user: ${user.email}`);
      return result;
    } catch (error) {
      this.logger.error(`Set password error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Change existing password
   * POST /auth/change-password
   */
  @Post('change-password')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change existing password' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async changePassword(@Req() req: Request, @Body() changePasswordData: ChangePasswordDto) {
    try {
      const user = req.user as any;
      
      if (changePasswordData.newPassword !== changePasswordData.confirmPassword) {
        throw new BadRequestException('New passwords do not match');
      }

      const result = await this.authService.changePassword(
        user.userId,
        changePasswordData.currentPassword,
        changePasswordData.newPassword
      );
      
      this.logger.log(`Password changed for user: ${user.email}`);
      return result;
    } catch (error) {
      this.logger.error(`Change password error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Check if user has a password set
   * GET /auth/has-password
   */
  @Get('has-password')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Check if user has a password set' })
  @ApiResponse({ status: 200, description: 'Password status returned' })
  @UseGuards(JwtAuthGuard)
  async hasPassword(@Req() req: Request) {
    try {
      const user = req.user as any;
      const result = await this.authService.hasPassword(user.userId);
      
      return result;
    } catch (error) {
      this.logger.error(`Check password error: ${error.message}`, error.stack);
      throw error;
    }
  }
}
