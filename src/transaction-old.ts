import { Uint64LE } from "int64-buffer";

export type TransactionDTO = {
	version: number;
	inputs: InputDTO[];
	outputs: OutputDTO[];
	locktime: number;
}

export type InputDTO = {
	previousTransactionHash: string;
	previousTransactionOutputIndex: number;
	signatureScript: string;
	sequence: number;
}

export type OutputDTO = {
	value: number;
	outputScript: string;
}


/* BITCOIN TRANSACTION PROTOCOL - Bytewise Structure
    * version (32 bit)
    * number of inputs (varint)
  	- for each input:
    * previous transaction hash (hash256, little-endian)
    * previous transaction index (32-bit)
		* previous transaction script length (varint)
    * previous transaction script (data)
    * input sequence (32-bit)
		---
    * number of outputs (varint)
    - for each output:    
    * output value (64-bit)
		* output script length (varint)
    * output script (data)
    ---
    * locktime (32-bit)
    * sighash (32-bit)
  */
export class Transaction {
  // input sequence (32bit little endian)
  static SEQUENCE = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
  static OP_DUP = 0x76;
  static OP_HASH160 = 0xa9;
  static OP_EQUALVERIFY = 0x88;
  static OP_CHECKSIG = 0xac;


	static serialize(transaction: TransactionDTO) {
    // turn transaction object into a serialized big string like this:
    // version + inputs + outputs + locktime + sighash
    // example string output: "0100000001...00000000"

    // version (32bit)
    const version = Buffer.alloc(4);
    version.writeUInt32LE(transaction.version);

    // number of inputs (varint)
    const numberOfInputs = Buffer.alloc(1);
    numberOfInputs.writeUInt8(transaction.inputs.length);

    // inputs
    const inputs = transaction.inputs.map(input => this.convertInputToBytes(input));
    const inputsBytes = Buffer.concat(inputs.flat());

    // number of outputs (varint)
    const numberOfOutputs = Buffer.alloc(1);
    numberOfOutputs.writeUInt8(transaction.outputs.length);

    // outputs
    const outputs = transaction.outputs.map(output => this.convertOutputToBytes(output));
    const outputsBytes = Buffer.concat(outputs.flat());

    // locktime (32bit)
    const locktime = Buffer.alloc(4);
    locktime.writeUInt32LE(transaction.locktime);

    // sighash (32bit)
    const sighash = Buffer.alloc(4);
    sighash.writeUInt32LE(0);

    const transactionBytes = [version, numberOfInputs, inputsBytes, numberOfOutputs, outputsBytes, locktime, sighash];

    return Buffer.concat(transactionBytes).toString('hex');    
	}

  static convertInputToBytes(input: InputDTO) {
    
    const previousTransactionHash = Buffer.from(input.previousTransactionHash, 'hex').reverse();

    const previousTransactionOutputIndex = Buffer.alloc(4);
    previousTransactionOutputIndex.writeUInt32LE(input.previousTransactionOutputIndex);

    const signatureScript = Buffer.from(input.signatureScript, 'hex');

    const sequence = Buffer.from(Transaction.SEQUENCE);

    const inputBytes = [previousTransactionHash, previousTransactionOutputIndex, signatureScript, sequence];

    return inputBytes;
  }

  static convertOutputToBytes(output: OutputDTO) {    
    
    const value = new Uint64LE(output.value).toBuffer();

    const outputScriptLength = Buffer.alloc(1)
    outputScriptLength.writeUInt8(output.outputScript.length); 

    const outputScript = Buffer.from(output.outputScript, 'hex');

    const outputBytes = [value, outputScriptLength, outputScript];

    return outputBytes;
  }

  static isValidOutputScript(outputScript: string) {
    // verify for standard output script

    // verify OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG    
    const scriptBuffer = Buffer.from(outputScript, 'hex');

    if(scriptBuffer.length !== 25) {
      throw new Error('Invalid output script');
    }

    if (scriptBuffer[0] !== this.OP_DUP) {
      throw new Error('Invalid script op code (different from OP_DUP)');
    }

    if (scriptBuffer[1] !== this.OP_HASH160) {
      throw new Error('Invalid script op code (different from OP_HASH160)');
    }

    if (scriptBuffer[2] !== 0x14) {
      throw new Error('Invalid pubKeyHash length');
    }

    if (scriptBuffer[23] !== this.OP_EQUALVERIFY) {
      throw new Error('Invalid script op code (different from OP_EQUALVERIFY)');
    }

    if (scriptBuffer[24] !== this.OP_CHECKSIG) {
      throw new Error('Invalid script op code (different from OP_CHECKSIG)');
    }

    return true;
  }

  static isValidInputScript(inputScript: string) {
    // verify [signature] [pubKey]

    // verify signature length
    const scriptBuffer = Buffer.from(inputScript, 'hex');

    // signature length

  }
}
