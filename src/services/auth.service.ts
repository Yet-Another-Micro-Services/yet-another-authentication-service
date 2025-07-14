import { Injectable, UnauthorizedException, BadRequestException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from './user.service';
import { User, UserDocument } from '../schemas/user.schema';
import { AuthResponseDto, SignUpDto, SignInDto } from '../dto/auth.dto';

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
