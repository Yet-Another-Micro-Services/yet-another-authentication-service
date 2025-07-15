import { Test, TestingModule } from '@nestjs/testing';
import { MongooseModule } from '@nestjs/mongoose';
import { startInMemoryMongoDB, stopInMemoryMongoDB } from '../src/config/test-db.config';

export class TestDatabase {
  private static mongoUri: string;

  static async setupTestDB(): Promise<string> {
    if (!this.mongoUri) {
      this.mongoUri = await startInMemoryMongoDB();
    }
    return this.mongoUri;
  }

  static async teardownTestDB(): Promise<void> {
    if (this.mongoUri) {
      await stopInMemoryMongoDB();
      this.mongoUri = '';
    }
  }

  static getMongooseTestModule() {
    return MongooseModule.forRootAsync({
      useFactory: async () => ({
        uri: await this.setupTestDB(),
      }),
    });
  }
}

// Global test setup and teardown
beforeAll(async () => {
  await TestDatabase.setupTestDB();
});

afterAll(async () => {
  await TestDatabase.teardownTestDB();
});
