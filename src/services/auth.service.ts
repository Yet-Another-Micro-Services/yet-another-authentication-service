import { Injectable, UnauthorizedException, BadRequestException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from './user.service';
import { User, UserDocument, OAuthProvider } from '../schemas/user.schema';
import { AuthResponseDto, OAuthAccountDto, SignUpDto, SignInDto } from '../dto/auth.dto';

export interface GoogleUserInfo {
  id: string;
  email: string;
  name: string;
  picture?: string;
  verified_email: boolean;
}

export interface JwtPayload {
  sub: string;
  email: string;
  name: string;
  iat?: number;
  exp?: number;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  /**
   * Handle user registration with email and password
   * @param signUpData - User registration data
   * @returns Authentication response with JWT tokens
   */
  async signUp(signUpData: SignUpDto): Promise<AuthResponseDto> {
    try {
      const user = await this.userService.createUserWithPassword(signUpData);
      
      this.logger.log(`New user registered: ${user.email}`);
      
      // Generate JWT tokens
      const tokens = await this.generateTokens(user);

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
      this.logger.error(`Sign up error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Handle user login with email/username and password
   * @param signInData - User login data
   * @returns Authentication response with JWT tokens
   */
  async signIn(signInData: SignInDto): Promise<AuthResponseDto> {
    try {
      const user = await this.userService.validatePassword(
        signInData.emailOrUsername,
        signInData.password,
      );

      if (!user) {
        throw new UnauthorizedException('Invalid email/username or password');
      }

      // Check if user account is active
      if (!user.isActive) {
        throw new UnauthorizedException('User account is deactivated');
      }

      // Update last login
      await this.userService.updateLastLogin(user._id.toString());

      this.logger.log(`User signed in: ${user.email}`);

      // Generate JWT tokens
      const tokens = await this.generateTokens(user);

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
      this.logger.error(`Sign in error: ${error.message}`, error.stack);
      throw error;
    }
  }
  async googleAuth(
    googleUserInfo: GoogleUserInfo,
    accessToken: string,
    refreshToken?: string,
  ): Promise<AuthResponseDto> {
    try {
      // Validate Google user info
      if (!googleUserInfo.verified_email) {
        throw new BadRequestException('Google account email is not verified');
      }

      // Create OAuth account data
      const oauthAccount: OAuthAccountDto = {
        provider: OAuthProvider.GOOGLE,
        providerId: googleUserInfo.id,
        email: googleUserInfo.email,
        accessToken,
        refreshToken,
      };

      // Look for existing user by OAuth provider and ID
      let user = await this.userService.findByOAuthProvider(
        OAuthProvider.GOOGLE,
        googleUserInfo.id,
      );

      if (user) {
        // User exists, verify email consistency
        const isEmailValid = await this.validateOAuthEmailConsistency(
          user,
          googleUserInfo.email,
        );

        if (!isEmailValid) {
          throw new UnauthorizedException(
            'OAuth email does not match any registered email for this account',
          );
        }

        // Update OAuth account info
        user = await this.userService.addOAuthAccount(user._id.toString(), oauthAccount);
      } else {
        // Check if user exists with same email from different provider
        const existingUserByEmail = await this.userService.findByEmail(googleUserInfo.email);
        
        if (existingUserByEmail) {
          // Merge accounts - add Google OAuth to existing user
          user = await this.userService.addOAuthAccount(
            existingUserByEmail._id.toString(),
            oauthAccount,
          );
          this.logger.log(`Merged Google account with existing user: ${user.email}`);
        } else {
          // Create new user
          user = await this.userService.createUser({
            email: googleUserInfo.email,
            name: googleUserInfo.name,
            profilePicture: googleUserInfo.picture,
            oauthAccount,
          });
          this.logger.log(`Created new user via Google OAuth: ${user.email}`);
        }
      }

      // Check if user account is active
      if (!user.isActive) {
        throw new UnauthorizedException('User account is deactivated');
      }

      // Generate JWT tokens
      const tokens = await this.generateTokens(user);

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
      this.logger.error(`Google auth error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Handle GitHub OAuth authentication
   * @param githubUserInfo - GitHub user information
   * @param accessToken - GitHub access token
   * @param refreshToken - GitHub refresh token (optional)
   * @returns Authentication response with JWT tokens
   */
  async githubAuth(
    githubUserInfo: GoogleUserInfo, // We can reuse the same interface
    accessToken: string,
    refreshToken?: string,
  ): Promise<AuthResponseDto> {
    try {
      // Create OAuth account data
      const oauthAccount: OAuthAccountDto = {
        provider: OAuthProvider.GITHUB, // We need to add this to the enum
        providerId: githubUserInfo.id,
        email: githubUserInfo.email,
        accessToken,
        refreshToken,
      };

      // Look for existing user by OAuth provider and ID
      let user = await this.userService.findByOAuthProvider(
        OAuthProvider.GITHUB,
        githubUserInfo.id,
      );

      if (user) {
        // User exists, verify email consistency
        const isEmailValid = await this.validateOAuthEmailConsistency(
          user,
          githubUserInfo.email,
        );

        if (!isEmailValid) {
          throw new UnauthorizedException(
            'OAuth email does not match any registered email for this account',
          );
        }

        // Update OAuth account info
        user = await this.userService.addOAuthAccount(user._id.toString(), oauthAccount);
      } else {
        // Check if user exists with same email from different provider
        const existingUserByEmail = await this.userService.findByEmail(githubUserInfo.email);
        
        if (existingUserByEmail) {
          // Merge accounts - add GitHub OAuth to existing user
          user = await this.userService.addOAuthAccount(
            existingUserByEmail._id.toString(),
            oauthAccount,
          );
          this.logger.log(`Merged GitHub account with existing user: ${user.email}`);
        } else {
          // Create new user
          user = await this.userService.createUser({
            email: githubUserInfo.email,
            name: githubUserInfo.name,
            profilePicture: githubUserInfo.picture,
            oauthAccount,
          });
          this.logger.log(`Created new user via GitHub OAuth: ${user.email}`);
        }
      }

      // Check if user account is active
      if (!user.isActive) {
        throw new UnauthorizedException('User account is deactivated');
      }

      // Generate JWT tokens
      const tokens = await this.generateTokens(user);

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
      this.logger.error(`GitHub auth error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Validate JWT token and return user information
   * @param token - JWT token
   * @returns User document
   */
  async validateToken(token: string): Promise<UserDocument> {
    try {
      const payload = this.jwtService.verify(token) as JwtPayload;
      const user = await this.userService.findById(payload.sub);
      
      if (!user.isActive) {
        throw new UnauthorizedException('User account is deactivated');
      }

      return user;
    } catch (error) {
      this.logger.error(`Token validation error: ${error.message}`);
      throw new UnauthorizedException('Invalid token');
    }
  }

  /**
   * Refresh JWT tokens
   * @param refreshToken - Refresh token
   * @returns New access and refresh tokens
   */
  async refreshTokens(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      const payload = this.jwtService.verify(refreshToken) as JwtPayload;
      const user = await this.userService.findById(payload.sub);
      
      if (!user.isActive) {
        throw new UnauthorizedException('User account is deactivated');
      }

      return await this.generateTokens(user);
    } catch (error) {
      this.logger.error(`Token refresh error: ${error.message}`);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Generate JWT access and refresh tokens
   * @param user - User document
   * @returns Access and refresh tokens
   */
  async generateTokens(user: UserDocument): Promise<{ accessToken: string; refreshToken: string }> {
    const payload: JwtPayload = {
      sub: user._id.toString(),
      email: user.email,
      name: user.name,
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.configService.get('JWT_EXPIRES_IN') || '15m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: '7d', // Refresh token expires in 7 days
    });

    return { accessToken, refreshToken };
  }

  /**
   * Validate OAuth email consistency with user's registered emails
   * @param user - User document
   * @param oauthEmail - OAuth provider email
   * @returns Boolean indicating if email is consistent
   */
  private async validateOAuthEmailConsistency(user: UserDocument, oauthEmail: string): Promise<boolean> {
    // Check if OAuth email matches user's primary email
    if (user.email.toLowerCase() === oauthEmail.toLowerCase()) {
      return true;
    }

    // Check if OAuth email matches any registered OAuth account email
    return user.oauthAccounts.some(
      account => account.email.toLowerCase() === oauthEmail.toLowerCase(),
    );
  }

  /**
   * Handle account merging when multiple OAuth providers have the same email
   * @param primaryUserId - Primary user ID
   * @param secondaryUserId - Secondary user ID
   * @returns Merged user document
   */
  async mergeAccounts(primaryUserId: string, secondaryUserId: string): Promise<UserDocument> {
    try {
      const mergedUser = await this.userService.mergeUsers(primaryUserId, secondaryUserId);
      this.logger.log(`Merged user accounts: ${primaryUserId} <- ${secondaryUserId}`);
      return mergedUser;
    } catch (error) {
      this.logger.error(`Account merge error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Logout user (invalidate tokens - in a real app, you'd maintain a blacklist)
   * @param userId - User ID
   * @returns Success message
   */
  async logout(userId: string): Promise<{ message: string }> {
    try {
      // Update last login timestamp
      await this.userService.updateLastLogin(userId);
      
      // In a production app, you would:
      // 1. Add tokens to a blacklist/revocation list
      // 2. Store blacklisted tokens in Redis with expiration
      // 3. Check blacklist during token validation
      
      this.logger.log(`User logged out: ${userId}`);
      return { message: 'Successfully logged out' };
    } catch (error) {
      this.logger.error(`Logout error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Get user profile information
   * @param userId - User ID
   * @returns User profile data
   */
  async getProfile(userId: string): Promise<any> {
    try {
      const user = await this.userService.findById(userId);
      
      return {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        profilePicture: user.profilePicture,
        isActive: user.isActive,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt,
        oauthAccounts: user.oauthAccounts.map(account => ({
          provider: account.provider,
          email: account.email,
          lastUsed: account.lastUsed,
        })),
      };
    } catch (error) {
      this.logger.error(`Get profile error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Set password for OAuth users who don't have one
   * @param userId - User ID
   * @param password - New password
   * @returns Success message
   */
  async setPassword(userId: string, password: string): Promise<{ message: string }> {
    try {
      // Check if user already has a password
      const hasPassword = await this.userService.hasPassword(userId);
      if (hasPassword) {
        throw new BadRequestException('User already has a password set. Use change password instead.');
      }

      await this.userService.updatePassword(userId, password);
      
      this.logger.log(`Password set for user: ${userId}`);
      return { message: 'Password set successfully' };
    } catch (error) {
      this.logger.error(`Set password error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Change existing password
   * @param userId - User ID
   * @param currentPassword - Current password
   * @param newPassword - New password
   * @returns Success message
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<{ message: string }> {
    try {
      // Verify current password
      const user = await this.userService.findById(userId);
      if (!user.hashedPassword) {
        throw new BadRequestException('User does not have a password set. Use set password instead.');
      }

      const isValidPassword = await this.userService.validatePassword(user.email, currentPassword);
      if (!isValidPassword) {
        throw new UnauthorizedException('Current password is incorrect');
      }

      await this.userService.updatePassword(userId, newPassword);
      
      this.logger.log(`Password changed for user: ${userId}`);
      return { message: 'Password changed successfully' };
    } catch (error) {
      this.logger.error(`Change password error: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Check if user has a password set
   * @param userId - User ID
   * @returns boolean indicating if user has password
   */
  async hasPassword(userId: string): Promise<{ hasPassword: boolean }> {
    try {
      const hasPassword = await this.userService.hasPassword(userId);
      return { hasPassword };
    } catch (error) {
      this.logger.error(`Check password error: ${error.message}`, error.stack);
      throw error;
    }
  }
}
