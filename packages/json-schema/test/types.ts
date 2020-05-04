import { SchemaDraft, Schema } from '../src/types';

export interface SchemaTestSuite {
  draft: SchemaDraft;
  name: string;
  tests: SchemaTest[];
}

export interface SchemaTest {
  description: string;
  schema: any;
  tests: SchemaTestCase[];
}

export interface SchemaTestCase {
  description: string;
  data: any;
  valid: boolean;
}

export interface Remote {
  name: string;
  schema: Schema;
}
