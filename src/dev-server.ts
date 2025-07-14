import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { startInMemoryMongoDB, stopInMemoryMongoDB } from './config/test-db.config';

async function bootstrapDev() {
  const logger = new Logger('DevBootstrap');
  
  try {
    // Start in-memory MongoDB
    const mongoUri = await startInMemoryMongoDB();
    
    // Set environment variable for the in-memory MongoDB
    process.env.MONGODB_URI = mongoUri;
    
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
        configService.get('FRONTEND_URL') || 'http://localhost:3000',
        configService.get('AUTH_SERVICE_BASE_URL') || 'http://localhost:3001',
      ],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    });
    
    // Global prefix for API routes
    app.setGlobalPrefix('api');

    // Swagger setup
    const { SwaggerModule, DocumentBuilder } = await import('@nestjs/swagger');
    const swaggerConfig = new DocumentBuilder()
      .setTitle('Authentication Service API')
      .setDescription('API documentation for the authentication service')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, swaggerConfig);
    SwaggerModule.setup('api/docs', app, document);

    const port = configService.get('AUTH_SERVICE_PORT') || 3001;
    await app.listen(port);
    
    logger.log(`🚀 Auth Service (Dev Mode) is running on: http://localhost:${port}`);
    logger.log(`📚 API Documentation: http://localhost:${port}/api`);
    logger.log(`🔍 Health Check: http://localhost:${port}/api/auth/health`);
    logger.log(`💾 Using In-Memory MongoDB: ${mongoUri}`);
    
    // Graceful shutdown
    process.on('SIGINT', async () => {
      logger.log('🛑 Received SIGINT, shutting down gracefully...');
      await app.close();
      await stopInMemoryMongoDB();
      process.exit(0);
    });

    process.on('SIGTERM', async () => {
      logger.log('🛑 Received SIGTERM, shutting down gracefully...');
      await app.close();
      await stopInMemoryMongoDB();
      process.exit(0);
    });
    
  } catch (error) {
    logger.error('❌ Error starting the development server', error);
    await stopInMemoryMongoDB();
    process.exit(1);
  }
}

bootstrapDev();
