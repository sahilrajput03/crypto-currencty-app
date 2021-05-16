import {createSign, createHash, generateKeyPairSync, createVerify} from 'crypto'

// 🧑︎‍🚀︎ Some terms:
// payer: who is paying the coin
//payee: who is receiving the coin

type Transaction = {amount: number; payer: string; payee: string}

// payer: public key of payer, payee: public key of payee
function Transaction(
	amount: number,
	payer: string,
	payee: string
): Transaction {
	// implement the toString method to stringify the whole this whole thing.
	return {amount, payer, payee}
}

function Block(
	prevHash: string,
	transaction: Transaction,
	timeStamp = Date.now()
) {
	const nonce = Math.round(Math.random() * 999_999_999) // What is nonce ? :: nonce meaning:: coined for one occasion. :: In cryptography, a nonce is an arbitrary number that can be used just once in a cryptographic communication.

	return {
		// TIP: Rename Block to `createBlock` for better readability.
		prevHash,
		transaction,
		timeStamp,
		nonce,
		hash: () => {
			const str = JSON.stringify(this)
			const hash = createHash('SHA256')

			hash.update(str).end()
			return hash.digest('hex')
		},
	}
}

let firstTransaction = Block('null', Transaction(100, 'genesis', 'satoshi'))

let BlockChain = [firstTransaction] //

const lastBlock = () => {
	return BlockChain[BlockChain.length - 1]
}

const addBlock = (
	transaction: Transaction,
	senderPublicKey: string,
	signature: string
) => {
	// const newBlock = Block(lastBlock().hash(), transaction)
	// BlockChain.push(newBlock)

	const verifier = createVerify('SHA256')
	verifier.update(JSON.stringify(transaction))

	const isValid = verifier.verify(senderPublicKey, signature)

	if (isValid) {
		const newBlock = Block(lastBlock().hash(), transaction)
		// ...
		// Before adding it to block chain one must add a proof of work system
		mine(newBlock.nonce)

		// ..
		BlockChain.push(newBlock)
	}
}

function mine(nonce: number) {
	let solution = 1
	console.log('🔨︎ mining...')

	while (true) {
		const hashInstance = createHash('MD5')
		const dataString = nonce + solution + '' // Adding "" to make data a string type.
		hashInstance.update(dataString).end()

		const computedHashAttempt = hashInstance.digest('hex') // calling the hashInstance.digest returns the computed hash.(src - node docs)

		if (computedHashAttempt.substr(0, 4) === '0000') {
			// ^^^ We are just checking if first 4 chars are equal to '0000' or not.
			console.log(`Solved: ${solution}`)
			return solution
		}

		return (solution += 1)
	}
}

const Wallet = () => {
	let publicKey: string // for receiving money.
	let privateKey: string // for spending money.

	//  To generate public-private keys we are using RSA Algorithm
	// Unlike SHA, RSA is a full encryption algorithm that can encrypt data and can decrypt data if you have the proper key to do so.
	// To encrypt a value we use the public key to encrypt it to ciphertext. And after that we can use private key to decrypt the ciphertext to it original value(plaintext).

	// P- private key; P+ public key
	// We are gonna use P- and P+ to create a digital signature. With signing we don't need to encrypt the message but instead create a hash of it, we then sign the hash with out private key then the message can be verified later using the public key. If anybody try to change the message it would produce a different hash in which case the verification would fail. And thats very important for our coin because we didn't have a signature then someone could intercept the transaction message and change the amount or change the payee with no way to detect anything was out of the ordinary.

	const keyPair = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: {type: 'spki', format: 'pem'},
		privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
	})

	publicKey = keyPair.privateKey
	privateKey = keyPair.publicKey

	let sendMoney = (amount: number, payeePublicKey: string) => {
		const transaction = Transaction(amount, publicKey, payeePublicKey)

		const signInstance = createSign('SHA256')
		// 🔽︎ We are signing using transaction data as value.
		signInstance.update(transaction.toString()).end()

		const signature = signInstance.sign(privateKey, 'base64') // *me: private key of the payer.
		//  We are signing with privatekey so that later we can verify the transaction using the privateKey.

		addBlock(transaction, publicKey, signature)
	}
}

// docs:
// For signature: If outputEncoding is provided a string is returned; otherwise a Buffer is returned.

// You get to define the encoding to signInstance.sign method in the second parameter otherwise it returns a buffer. Amazing api docs(nodejs) for understanding buffers: https://nodejs.org/api/buffer.html#buffer_buffers_and_character_encodings
