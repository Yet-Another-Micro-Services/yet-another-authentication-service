import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

// OAuth Provider enum
export enum OAuthProvider {
  GOOGLE = 'google',
  GITHUB = 'github',
  // Future providers can be added here
}

// OAuth Account subdocument
@Schema({ _id: false })
export class OAuthAccount {
  @Prop({ required: true, enum: OAuthProvider })
  provider: OAuthProvider;

  @Prop({ required: true })
  providerId: string;

  @Prop({ required: true })
  email: string;

  @Prop()
  accessToken?: string;

  @Prop()
  refreshToken?: string;

  @Prop({ default: Date.now })
  lastUsed: Date;
}

export const OAuthAccountSchema = SchemaFactory.createForClass(OAuthAccount);

// User schema
@Schema({ 
  timestamps: true,
  collection: 'users'
})
export class User extends Document {
  declare _id: Types.ObjectId;

  @Prop({ required: true, unique: true, lowercase: true })
  email: string;

  @Prop({ unique: true, sparse: true, lowercase: true })
  username?: string;

  @Prop({ required: true })
  name: string;

  @Prop()
  profilePicture?: string;

  @Prop()
  hashedPassword?: string;

  @Prop({ default: false })
  emailVerified: boolean;

  @Prop({ type: [OAuthAccountSchema], default: [] })
  oauthAccounts: OAuthAccount[];

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ default: Date.now })
  lastLogin: Date;

  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Create indexes for better query performance
UserSchema.index({ 'oauthAccounts.provider': 1, 'oauthAccounts.providerId': 1 });
UserSchema.index({ 'oauthAccounts.email': 1 });
UserSchema.index({ createdAt: -1 });

// Pre-save middleware to update timestamps
UserSchema.pre('save', function(next) {
  if (this.isModified() && !this.isNew) {
    this.updatedAt = new Date();
  }
  next();
});

export type UserDocument = User & Document;
