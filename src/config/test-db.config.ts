import { MongoMemoryServer } from 'mongodb-memory-server';

let mongod: MongoMemoryServer;

export const startInMemoryMongoDB = async (): Promise<string> => {
  mongod = await MongoMemoryServer.create({
    instance: {
      port: 27017, // Use default MongoDB port
      dbName: 'auth-service-test',
    },
  });
  
  const uri = mongod.getUri();
  console.log(`📦 In-memory MongoDB started at: ${uri}`);
  return uri;
};

export const stopInMemoryMongoDB = async (): Promise<void> => {
  if (mongod) {
    await mongod.stop();
    console.log('🛑 In-memory MongoDB stopped');
  }
};

export const getInMemoryMongoDBUri = (): string => {
  if (!mongod) {
    throw new Error('In-memory MongoDB is not started');
  }
  return mongod.getUri();
};
