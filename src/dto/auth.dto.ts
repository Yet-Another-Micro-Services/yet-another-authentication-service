import { IsEmail, IsString, IsOptional, IsUrl, IsEnum, MinLength, Matches } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { OAuthProvider } from '../schemas/user.schema';

export class SignUpDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  email: string;

  @ApiPropertyOptional({ example: 'username123' })
  @IsString()
  @IsOptional()
  username?: string;

  @ApiProperty({ example: 'John Doe' })
  @IsString()
  @MinLength(2)
  name: string;

  @ApiProperty({ example: 'StrongP@ssw0rd!' })
  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  password: string;

  @ApiPropertyOptional({ example: 'https://example.com/avatar.png' })
  @IsUrl()
  @IsOptional()
  profilePicture?: string;
}

export class SignInDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsString()
  emailOrUsername: string;

  @ApiProperty({ example: 'StrongP@ssw0rd!' })
  @IsString()
  password: string;
}

export class AuthResponseUser {
  @ApiProperty({ example: 'userId123' })
  id: string;
  @ApiProperty({ example: 'user@example.com' })
  email: string;
  @ApiProperty({ example: 'John Doe' })
  name: string;
  @ApiPropertyOptional({ example: 'https://example.com/avatar.png' })
  profilePicture?: string;
  @ApiProperty({ example: '2025-07-15T04:30:50.000Z' })
  lastLogin: Date;
}

export class AuthResponseDto {
  @ApiProperty({ example: 'jwt-access-token' })
  @IsString()
  accessToken: string;

  @ApiProperty({ example: 'jwt-refresh-token' })
  @IsString()
  refreshToken: string;

  @ApiProperty({ type: AuthResponseUser })
  user: AuthResponseUser;
}

export class OAuthAccountDto {
  @ApiProperty({ enum: OAuthProvider })
  @IsEnum(OAuthProvider)
  provider: OAuthProvider;

  @ApiProperty({ example: 'providerId123' })
  @IsString()
  providerId: string;

  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  email: string;

  @ApiPropertyOptional({ example: 'oauth-access-token' })
  @IsString()
  @IsOptional()
  accessToken?: string;

  @ApiPropertyOptional({ example: 'oauth-refresh-token' })
  @IsString()
  @IsOptional()
  refreshToken?: string;
}

export class SetPasswordDto {
  @ApiProperty({ example: 'StrongP@ssw0rd!' })
  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  password: string;

  @ApiProperty({ example: 'StrongP@ssw0rd!' })
  @IsString()
  confirmPassword: string;
}

export class ChangePasswordDto {
  @ApiProperty({ example: 'OldP@ssw0rd!' })
  @IsString()
  currentPassword: string;

  @ApiProperty({ example: 'NewP@ssw0rd!' })
  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  newPassword: string;

  @ApiProperty({ example: 'NewP@ssw0rd!' })
  @IsString()
  confirmPassword: string;
}
