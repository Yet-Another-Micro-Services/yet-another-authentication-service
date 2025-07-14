import { IsEmail, IsString, IsOptional, IsUrl, IsEnum, MinLength, Matches } from 'class-validator';
import { OAuthProvider } from '../schemas/user.schema';

export class SignUpDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsOptional()
  username?: string;

  @IsString()
  @MinLength(2)
  name: string;

  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  password: string;

  @IsUrl()
  @IsOptional()
  profilePicture?: string;
}

export class SignInDto {
  @IsString()
  emailOrUsername: string;

  @IsString()
  password: string;
}

export class AuthResponseDto {
  @IsString()
  accessToken: string;

  @IsString()
  refreshToken: string;

  user: {
    id: string;
    email: string;
    name: string;
    profilePicture?: string;
    lastLogin: Date;
  };
}

export class OAuthAccountDto {
  @IsEnum(OAuthProvider)
  provider: OAuthProvider;

  @IsString()
  providerId: string;

  @IsEmail()
  email: string;

  @IsString()
  @IsOptional()
  accessToken?: string;

  @IsString()
  @IsOptional()
  refreshToken?: string;
}

export class SetPasswordDto {
  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  password: string;

  @IsString()
  confirmPassword: string;
}

export class ChangePasswordDto {
  @IsString()
  currentPassword: string;

  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  newPassword: string;

  @IsString()
  confirmPassword: string;
}
