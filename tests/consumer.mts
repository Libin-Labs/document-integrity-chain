import { createIntegrityChain, verifyIntegrityChain } from '@lp-labs/document-integrity-chain';
import type {
  IntegrityEntry,
  IntegrityChain,
  IntegrityVerification,
} from '@lp-labs/document-integrity-chain';
const runtimeExports: unknown[] = [createIntegrityChain, verifyIntegrityChain];
type PublicTypes = IntegrityEntry | IntegrityChain | IntegrityVerification;
void runtimeExports;
let publicType!: PublicTypes;
void publicType;
