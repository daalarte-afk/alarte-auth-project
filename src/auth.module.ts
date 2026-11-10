import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersModule } from './users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

@Module({
    imports: [
        UsersModule,
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
            secret: process.env.JWT_ACCESS_TOKEN_SECRET || 'access_secret',
            signOptions: {
                expiresIn: (process.env.ACCESS_TOKEN_EXPIRES_IN || '900s') as any,
            },
        }),
    ],
    providers: [AuthService],
    exports: [AuthService],
})
export class AuthModule { }
