import { Injectable, ConflictException, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { User, UserDocument, OAuthProvider, OAuthAccount } from '../schemas/user.schema';
import { UpdateProfileDto, OAuthAccountDto, SignUpDto } from '../dto/auth.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
  ) {}

  /**
   * Find a user by email
   * @param email - User's email address
   * @returns User document or null
   */
  async findByEmail(email: string): Promise<UserDocument | null> {
    try {
      return await this.userModel.findOne({ email: email.toLowerCase() }).exec();
    } catch (error) {
      throw new Error(`Error finding user by email: ${error.message}`);
    }
  }

  /**
   * Find a user by username
   * @param username - User's username
   * @returns User document or null
   */
  async findByUsername(username: string): Promise<UserDocument | null> {
    try {
      return await this.userModel.findOne({ username: username.toLowerCase() }).exec();
    } catch (error) {
      throw new Error(`Error finding user by username: ${error.message}`);
    }
  }

  /**
   * Find a user by email or username
   * @param emailOrUsername - User's email or username
   * @returns User document or null
   */
  async findByEmailOrUsername(emailOrUsername: string): Promise<UserDocument | null> {
    try {
      const query = emailOrUsername.includes('@') 
        ? { email: emailOrUsername.toLowerCase() }
        : { username: emailOrUsername.toLowerCase() };
      
      return await this.userModel.findOne(query).exec();
    } catch (error) {
      throw new Error(`Error finding user by email or username: ${error.message}`);
    }
  }

  /**
   * Find a user by OAuth provider and provider ID
   * @param provider - OAuth provider
   * @param providerId - Provider's user ID
   * @returns User document or null
   */
  async findByOAuthProvider(provider: OAuthProvider, providerId: string): Promise<UserDocument | null> {
    try {
      return await this.userModel.findOne({
        'oauthAccounts.provider': provider,
        'oauthAccounts.providerId': providerId,
      }).exec();
    } catch (error) {
      throw new Error(`Error finding user by OAuth provider: ${error.message}`);
    }
  }

  /**
   * Find a user by OAuth provider email
   * @param provider - OAuth provider
   * @param email - Provider's email
   * @returns User document or null
   */
  async findByOAuthEmail(provider: OAuthProvider, email: string): Promise<UserDocument | null> {
    try {
      return await this.userModel.findOne({
        'oauthAccounts.provider': provider,
        'oauthAccounts.email': email.toLowerCase(),
      }).exec();
    } catch (error) {
      throw new Error(`Error finding user by OAuth email: ${error.message}`);
    }
  }

  /**
   * Create a new user with email and password
   * @param signUpData - User registration data
   * @returns Created user document
   */
  async createUserWithPassword(signUpData: SignUpDto): Promise<UserDocument> {
    try {
      // Check if user already exists by email
      const existingUserByEmail = await this.findByEmail(signUpData.email);
      if (existingUserByEmail) {
        throw new ConflictException('User with this email already exists');
      }

      // Check if username is taken (if provided)
      if (signUpData.username) {
        const existingUserByUsername = await this.findByUsername(signUpData.username);
        if (existingUserByUsername) {
          throw new ConflictException('Username is already taken');
        }
      }

      // Hash password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(signUpData.password, saltRounds);

      const user = new this.userModel({
        email: signUpData.email.toLowerCase(),
        username: signUpData.username?.toLowerCase(),
        name: signUpData.name,
        profilePicture: signUpData.profilePicture,
        hashedPassword,
        emailVerified: false, // In production, implement email verification
        lastLogin: new Date(),
      });

      return await user.save();
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      throw new Error(`Error creating user with password: ${error.message}`);
    }
  }

  /**
   * Validate user password
   * @param emailOrUsername - User's email or username
   * @param password - Plain text password
   * @returns User document if valid, null if invalid
   */
  async validatePassword(emailOrUsername: string, password: string): Promise<UserDocument | null> {
    try {
      const user = await this.findByEmailOrUsername(emailOrUsername);
      if (!user || !user.hashedPassword) {
        return null;
      }

      const isValidPassword = await bcrypt.compare(password, user.hashedPassword);
      return isValidPassword ? user : null;
    } catch (error) {
      throw new Error(`Error validating password: ${error.message}`);
    }
  }

  /**
   * Update user password
   * @param userId - User ID
   * @param newPassword - New plain text password
   * @returns Updated user document
   */
  async updatePassword(userId: string, newPassword: string): Promise<UserDocument> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
      
      user.hashedPassword = hashedPassword;
      return await user.save();
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error(`Error updating password: ${error.message}`);
    }
  }
  async createUser(userData: {
    email: string;
    name: string;
    profilePicture?: string;
    oauthAccount: OAuthAccountDto;
  }): Promise<UserDocument> {
    try {
      // Check if user already exists
      const existingUser = await this.findByEmail(userData.email);
      if (existingUser) {
        throw new ConflictException('User with this email already exists');
      }

      const user = new this.userModel({
        email: userData.email.toLowerCase(),
        name: userData.name,
        profilePicture: userData.profilePicture,
        oauthAccounts: [userData.oauthAccount],
        lastLogin: new Date(),
      });

      return await user.save();
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      throw new Error(`Error creating user: ${error.message}`);
    }
  }

  /**
   * Add OAuth account to existing user or merge accounts
   * @param userId - User ID
   * @param oauthAccount - OAuth account data
   * @returns Updated user document
   */
  async addOAuthAccount(userId: string, oauthAccount: OAuthAccountDto): Promise<UserDocument> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Check if OAuth account already exists
      const existingAccountIndex = user.oauthAccounts.findIndex(
        account => account.provider === oauthAccount.provider && account.providerId === oauthAccount.providerId
      );

      if (existingAccountIndex !== -1) {
        // Update existing account
        user.oauthAccounts[existingAccountIndex] = {
          ...user.oauthAccounts[existingAccountIndex],
          ...oauthAccount,
          lastUsed: new Date(),
        };
      } else {
        // Add new account
        user.oauthAccounts.push({
          ...oauthAccount,
          lastUsed: new Date(),
        });
      }

      user.lastLogin = new Date();
      return await user.save();
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error(`Error adding OAuth account: ${error.message}`);
    }
  }

  /**
   * Merge two user accounts when they have the same email
   * @param primaryUserId - Primary user ID (keep this one)
   * @param secondaryUserId - Secondary user ID (merge into primary)
   * @returns Updated primary user document
   */
  async mergeUsers(primaryUserId: string, secondaryUserId: string): Promise<UserDocument> {
    try {
      const primaryUser = await this.userModel.findById(primaryUserId);
      const secondaryUser = await this.userModel.findById(secondaryUserId);

      if (!primaryUser || !secondaryUser) {
        throw new NotFoundException('One or both users not found');
      }

      // Merge OAuth accounts
      for (const oauthAccount of secondaryUser.oauthAccounts) {
        const existingAccountIndex = primaryUser.oauthAccounts.findIndex(
          account => account.provider === oauthAccount.provider && account.providerId === oauthAccount.providerId
        );

        if (existingAccountIndex === -1) {
          primaryUser.oauthAccounts.push(oauthAccount);
        }
      }

      // Update last login and save
      primaryUser.lastLogin = new Date();
      await primaryUser.save();

      // Delete secondary user
      await this.userModel.findByIdAndDelete(secondaryUserId);

      return primaryUser;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error(`Error merging users: ${error.message}`);
    }
  }

  /**
   * Update user profile
   * @param userId - User ID
   * @param updateData - Profile update data
   * @returns Updated user document
   */
  async updateProfile(userId: string, updateData: UpdateProfileDto): Promise<UserDocument> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      // If email is being updated, check if it conflicts with OAuth accounts
      if (updateData.email && updateData.email !== user.email) {
        const emailMatches = user.oauthAccounts.some(
          account => account.email.toLowerCase() === updateData.email!.toLowerCase()
        );
        
        if (!emailMatches) {
          throw new BadRequestException(
            'Email update failed: New email must match at least one OAuth account email'
          );
        }

        // Check if another user already has this email
        const existingUser = await this.findByEmail(updateData.email);
        if (existingUser && existingUser._id.toString() !== userId) {
          throw new ConflictException('Another user already has this email');
        }
      }

      // Update user fields
      Object.assign(user, updateData);
      if (updateData.email) {
        user.email = updateData.email.toLowerCase();
      }

      return await user.save();
    } catch (error) {
      if (error instanceof NotFoundException || error instanceof BadRequestException || error instanceof ConflictException) {
        throw error;
      }
      throw new Error(`Error updating profile: ${error.message}`);
    }
  }

  /**
   * Update user's last login timestamp
   * @param userId - User ID
   * @returns Updated user document
   */
  async updateLastLogin(userId: string): Promise<UserDocument> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      user.lastLogin = new Date();
      return await user.save();
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error(`Error updating last login: ${error.message}`);
    }
  }

  /**
   * Deactivate user account
   * @param userId - User ID
   * @returns Updated user document
   */
  async deactivateUser(userId: string): Promise<UserDocument> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      user.isActive = false;
      return await user.save();
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error(`Error deactivating user: ${error.message}`);
    }
  }

  /**
   * Get user by ID
   * @param userId - User ID
   * @returns User document
   */
  async findById(userId: string): Promise<UserDocument> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }
      return user;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error(`Error finding user by ID: ${error.message}`);
    }
  }

  /**
   * Validate OAuth account email against user's primary email
   * @param userId - User ID
   * @param oauthEmail - OAuth provider email
   * @returns boolean indicating if email is valid
   */
  async validateOAuthEmail(userId: string, oauthEmail: string): Promise<boolean> {
    try {
      const user = await this.findById(userId);
      return user.oauthAccounts.some(
        account => account.email.toLowerCase() === oauthEmail.toLowerCase()
      );
    } catch (error) {
      throw new Error(`Error validating OAuth email: ${error.message}`);
    }
  }

  /**
   * Set password for OAuth users who don't have one
   * @param userId - User ID
   * @param newPassword - New plain text password
   * @returns Updated user document
   */
  async setPassword(userId: string, newPassword: string): Promise<UserDocument> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Check if user already has a password
      if (user.hashedPassword) {
        throw new BadRequestException('User already has a password. Use change password instead.');
      }

      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
      
      user.hashedPassword = hashedPassword;
      return await user.save();
    } catch (error) {
      if (error instanceof NotFoundException || error instanceof BadRequestException) {
        throw error;
      }
      throw new Error(`Error setting password: ${error.message}`);
    }
  }

  /**
   * Change password for users who already have one
   * @param userId - User ID
   * @param currentPassword - Current password for verification
   * @param newPassword - New plain text password
   * @returns Updated user document
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<UserDocument> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Check if user has a password
      if (!user.hashedPassword) {
        throw new BadRequestException('User does not have a password set. Use set password instead.');
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, user.hashedPassword);
      if (!isValidPassword) {
        throw new BadRequestException('Current password is incorrect');
      }

      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
      
      user.hashedPassword = hashedPassword;
      return await user.save();
    } catch (error) {
      if (error instanceof NotFoundException || error instanceof BadRequestException) {
        throw error;
      }
      throw new Error(`Error changing password: ${error.message}`);
    }
  }

  /**
   * Check if user has a password set
   * @param userId - User ID
   * @returns boolean indicating if user has password
   */
  async hasPassword(userId: string): Promise<boolean> {
    try {
      const user = await this.userModel.findById(userId).exec();
      if (!user) {
        throw new NotFoundException('User not found');
      }
      
      return !!user.hashedPassword;
    } catch (error) {
      throw new Error(`Error checking password status: ${error.message}`);
    }
  }
}
