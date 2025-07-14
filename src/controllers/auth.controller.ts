import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  UseGuards, 
  Req, 
  Res, 
  HttpCode, 
  HttpStatus,
  BadRequestException,
  Logger,
  Put,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';
import { UserService } from '../services/user.service';
import { GoogleAuthGuard } from '../guards/google-auth.guard';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { UpdateProfileDto, OAuthAccountDto, SignUpDto, SignInDto, SetPasswordDto, ChangePasswordDto } from '../dto/auth.dto';
import { OAuthProvider } from '../schemas/user.schema';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private authService: AuthService,
    private userService: UserService,
    private configService: ConfigService,
  ) {}

  /**
   * Initiate Google OAuth authentication
   * GET /auth/google
   */
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth(@Req() req: Request) {
    // This route is handled by Google OAuth strategy
    // The actual authentication happens in the callback
  }

  /**
   * Google OAuth callback
   * GET /auth/google/callback
   */
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthCallback(@Req() req: Request, @Res() res: Response) {
    try {
      const authResult = req.user as any;
      
      if (!authResult) {
        throw new BadRequestException('Authentication failed');
      }

      // Redirect to frontend with tokens
      const frontendUrl = this.configService.get('FRONTEND_URL');
      const redirectUrl = `${frontendUrl}/auth/callback?token=${authResult.accessToken}&refresh=${authResult.refreshToken}`;
      
      this.logger.log(`Google auth successful for user: ${authResult.user.email}`);
      res.redirect(redirectUrl);
    } catch (error) {
      this.logger.error(`Google auth callback error: ${error.message}`, error.stack);
      const frontendUrl = this.configService.get('FRONTEND_URL');
      res.redirect(`${frontendUrl}/auth/error?message=${encodeURIComponent(error.message)}`);
    }
  }

  /**
   * Manual Google token verification (for direct API calls)
   * POST /auth/google/verify
   */
  @Post('google/verify')
  @HttpCode(HttpStatus.OK)
  async verifyGoogleToken(@Body() body: { access_token: string }) {
    try {
      if (!body.access_token) {
        throw new BadRequestException('Access token is required');
      }

      // Verify token with Google API
      const response = await fetch(
        `https://www.googleapis.com/oauth2/v1/userinfo?access_token=${body.access_token}`,
      );

      if (!response.ok) {
        throw new BadRequestException('Invalid Google access token');
      }

      const googleUserInfo = await response.json();
      
      // Authenticate user
      const authResult = await this.authService.googleAuth(
        googleUserInfo,
        body.access_token,
      );

      this.logger.log(`Google token verification successful for user: ${authResult.user.email}`);
      return authResult;
    } catch (error) {
      this.logger.error(`Google token verification error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Refresh JWT tokens
   * POST /auth/refresh
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(@Body() body: { refresh_token: string }) {
    try {
      if (!body.refresh_token) {
        throw new BadRequestException('Refresh token is required');
      }

      const tokens = await this.authService.refreshTokens(body.refresh_token);
      
      this.logger.log('Token refresh successful');
      return tokens;
    } catch (error) {
      this.logger.error(`Token refresh error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Get current user profile
   * GET /auth/profile
   */
  @Get('profile')
  @UseGuards(JwtAuthGuard)
  async getProfile(@Req() req: Request) {
    try {
      const user = req.user as any;
      const profile = await this.authService.getProfile(user.userId);
      
      return profile;
    } catch (error) {
      this.logger.error(`Get profile error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Update user profile
   * PUT /auth/profile
   */
  @Put('profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(@Req() req: Request, @Body() updateData: UpdateProfileDto) {
    try {
      const user = req.user as any;
      const updatedUser = await this.userService.updateProfile(user.userId, updateData);
      
      this.logger.log(`Profile updated for user: ${updatedUser.email}`);
      return {
        id: updatedUser._id.toString(),
        email: updatedUser.email,
        name: updatedUser.name,
        profilePicture: updatedUser.profilePicture,
        lastLogin: updatedUser.lastLogin,
      };
    } catch (error) {
      this.logger.error(`Profile update error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Logout user
   * POST /auth/logout
   */
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request) {
    try {
      const user = req.user as any;
      const result = await this.authService.logout(user.userId);
      
      this.logger.log(`User logged out: ${user.email}`);
      return result;
    } catch (error) {
      this.logger.error(`Logout error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Validate JWT token
   * GET /auth/validate
   */
  @Get('validate')
  @UseGuards(JwtAuthGuard)
  async validateToken(@Req() req: Request) {
    try {
      const user = req.user as any;
      
      return {
        valid: true,
        user: {
          id: user.userId,
          email: user.email,
          name: user.name,
        },
      };
    } catch (error) {
      this.logger.error(`Token validation error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Health check endpoint
   * GET /auth/health
   */
  @Get('health')
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
   * Handle PKCE authentication from frontend (NextAuth.js)
   * POST /auth/pkce/google
   */
  @Post('pkce/google')
  @HttpCode(HttpStatus.OK)
  async handleGooglePKCE(@Body() body: { 
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    user_info?: any;
  }) {
    try {
      if (!body.access_token) {
        throw new BadRequestException('Access token is required');
      }

      let googleUserInfo;

      // If user_info is provided directly from frontend, use it
      if (body.user_info) {
        googleUserInfo = {
          id: body.user_info.sub || body.user_info.id,
          email: body.user_info.email,
          name: body.user_info.name,
          picture: body.user_info.picture,
          verified_email: body.user_info.email_verified !== false,
        };
      } else {
        // Otherwise, verify token with Google API
        const response = await fetch(
          `https://www.googleapis.com/oauth2/v1/userinfo?access_token=${body.access_token}`,
        );

        if (!response.ok) {
          throw new BadRequestException('Invalid Google access token');
        }

        const userInfo = await response.json();
        googleUserInfo = {
          id: userInfo.id,
          email: userInfo.email,
          name: userInfo.name,
          picture: userInfo.picture,
          verified_email: userInfo.verified_email !== false,
        };
      }

      // Authenticate user using the auth service
      const authResult = await this.authService.googleAuth(
        googleUserInfo,
        body.access_token,
        body.refresh_token,
      );

      this.logger.log(`PKCE Google auth successful for user: ${authResult.user.email}`);
      return authResult;
    } catch (error) {
      this.logger.error(`PKCE Google auth error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Handle PKCE authentication for GitHub from frontend (NextAuth.js)
   * POST /auth/pkce/github
   */
  @Post('pkce/github')
  @HttpCode(HttpStatus.OK)
  async handleGitHubPKCE(@Body() body: { 
    access_token: string;
    refresh_token?: string;
    user_info?: any;
  }) {
    try {
      if (!body.access_token) {
        throw new BadRequestException('Access token is required');
      }

      let githubUserInfo;

      // If user_info is provided directly from frontend, use it
      if (body.user_info) {
        githubUserInfo = {
          id: body.user_info.id.toString(),
          email: body.user_info.email,
          name: body.user_info.name || body.user_info.login,
          picture: body.user_info.avatar_url,
          verified_email: true, // GitHub emails are generally verified
        };
      } else {
        // Otherwise, verify token with GitHub API
        const userResponse = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `token ${body.access_token}`,
            'Accept': 'application/vnd.github.v3+json',
          },
        });

        if (!userResponse.ok) {
          throw new BadRequestException('Invalid GitHub access token');
        }

        const userInfo = await userResponse.json();
        
        // Get user emails if email is not public
        if (!userInfo.email) {
          const emailResponse = await fetch('https://api.github.com/user/emails', {
            headers: {
              'Authorization': `token ${body.access_token}`,
              'Accept': 'application/vnd.github.v3+json',
            },
          });

          if (emailResponse.ok) {
            const emails = await emailResponse.json();
            const primaryEmail = emails.find(email => email.primary && email.verified);
            userInfo.email = primaryEmail?.email;
          }
        }

        if (!userInfo.email) {
          throw new BadRequestException('Unable to retrieve verified email from GitHub');
        }

        githubUserInfo = {
          id: userInfo.id.toString(),
          email: userInfo.email,
          name: userInfo.name || userInfo.login,
          picture: userInfo.avatar_url,
          verified_email: true,
        };
      }

      // Authenticate user using GitHub auth method
      const authResult = await this.authService.githubAuth(
        githubUserInfo,
        body.access_token,
        body.refresh_token,
      );

      this.logger.log(`PKCE GitHub auth successful for user: ${authResult.user.email}`);
      return authResult;
    } catch (error) {
      this.logger.error(`PKCE GitHub auth error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Sync NextAuth.js session with backend auth service
   * POST /auth/sync
   */
  @Post('sync')
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
