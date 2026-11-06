import packageExports = require('@lp-labs/document-integrity-chain');
import type {
  IntegrityEntry,
  IntegrityChain,
  IntegrityVerification,
} from '@lp-labs/document-integrity-chain';
const runtimeExports: unknown[] = [
  packageExports.createIntegrityChain,
  packageExports.verifyIntegrityChain,
];
type PublicTypes = IntegrityEntry | IntegrityChain | IntegrityVerification;
void runtimeExports;
let publicType!: PublicTypes;
void publicType;
