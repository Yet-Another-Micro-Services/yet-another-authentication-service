import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  
  try {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);
    
    // Global validation pipe
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }));
    
    // CORS configuration
    app.enableCors({
      origin: [
        configService.get('FRONTEND_URL') || configService.get('AUTH_SERVICE_BASE_URL'),
      ],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    });
    
    // Global prefix for API routes
    app.setGlobalPrefix('api');

    const port = configService.get('AUTH_SERVICE_PORT') || 3001;
    await app.listen(port);
    
    logger.log(`🚀 Auth Service is running on: http://localhost:${port}`);
    logger.log(`📚 API Documentation: http://localhost:${port}/api`);
    logger.log(`🔍 Health Check: http://localhost:${port}/api/auth/health`);
    
  } catch (error) {
    logger.error('❌ Error starting the application', error);
    process.exit(1);
  }
}

bootstrap();
