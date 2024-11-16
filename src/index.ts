import { InputDTO, OutputDTO, Transaction, TransactionDTO } from "./transaction-old";

export default function main() {

    const input: InputDTO = {
        previousTransactionHash: '',
        previousTransactionOutputIndex: 0,
        signatureScript: '',
        sequence: 0
    }

    const output: OutputDTO = {
        value: 100000000,
        outputScript: 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g'
    }

    const transaction: TransactionDTO = {
        version: 1,
        inputs: [input],
        outputs: [output],
        locktime: 0
    }

    const serializedTransaction = Transaction.serialize(transaction);

    console.log('serializedTransaction', serializedTransaction);
}

main();