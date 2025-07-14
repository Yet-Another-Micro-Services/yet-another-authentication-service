import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../services/user.service';
import { JwtPayload } from '../services/auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private userService: UserService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET')!,
    });
  }

  async validate(payload: JwtPayload) {
    try {
      const user = await this.userService.findById(payload.sub);
      
      if (!user.isActive) {
        throw new UnauthorizedException('User account is deactivated');
      }
      
      // Return user info for request context
      return {
        userId: payload.sub,
        email: payload.email,
        name: payload.name,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
