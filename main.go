package main

import (
	"bytes"
	"crypto/rand"
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"io/ioutil"
	"time"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"golang.org/x/crypto/nacl/secretbox"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"strings"
)

const (
	kmsKeyName = "<your_aws_key_here>" // Must already exist in kms
)

var collection *mongo.Collection
var ctx = context.TODO()

// Model of a collection in MongoDB to encrypt and decrypt
// The format bson of a data is to use in .Decode of mongo cursor
// The format json of a data is to use in return for some front-end
type Tasks struct {
	ID 	 string 	`json:"id" bson:"id"`
	Name string 	`json:"name" bson:"name"`
	Desc string 	`json:"desc" bson:"desc"`
	Cost float64 	`json:"cost" bson:"cost"`
	Done bool		`json:"done" bson:"done"`
	Date *time.Time `json:"date" bson:"date"`
}

func main() {

	clientOptions := options.Client().ApplyURI("mongodb+srv://<your_password>@<your_cluster>.yor2omb.mongodb.net/?retryWrites=true&w=majority")
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Making a ping in mongo client to verify connection 
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Starting the session to use this in a client from kmsClient
	sess := session.Must(session.NewSession())
	kmsClient := kms.New(sess, aws.NewConfig().WithRegion("us-east-1"))

	// Using a global variable to create a mongo collection based on a specific database
	collection = client.Database("<your_database_name>").Collection("<your_collection_name>")

	// Calling a function to encrypt data from collection
	getAllTasksAndEncrypt(kmsClient)

}

// Function to encrypt data and sending to MongoDB collection
func getAllTasksAndEncrypt(kmsClient *kms.KMS) {

	// Here, you can select the fields of collection
	cur, err := collection.Aggregate(ctx, mongo.Pipeline{
		bson.D{
			{"$project",
				bson.D{
					{"id", 1},
					{"name", 1},
					{"desc", 1},
					{"cost", 1},
					{"done", 1},
					{"date", 1},
				},
			},
		},
	})

	if err != nil {
		log.Fatal("Cannot make an aggregate cursor of a collection in mongo")
	}

	// Making a cursor.Next() with a context to Decode informations from cursor
	for cur.Next(context.Background()) {

		var t Tasks
		err := cur.Decode(&t)

		if err != nil {
			log.Fatal("Cannot decode the cursor from MongoDB")
		}

		// The ID not need a encrypt, because
		SendEncryptedString(t.ID, "name", t.Name, kmsClient)
		SendEncryptedString(t.ID, "desc", t.Desc, kmsClient)
		SendEncryptedFloat(t.ID, "cost", t.Cost, kmsClient)
		SendEncryptedBool(t.ID, "done", t.Done, kmsClient)
		// In this case, we need to conversta a data to string and call a functinon after
		Date := (t.Date).Format("2006-01-02 15:04:05")
		SendEncryptedStringData(t.ID, "date", Date, kmsClient)

	}

	cur.Close(ctx)

}

// Defining certain lengths related to AWS KMS
const (
	keyLength   = 32
	nonceLength = 24
)

// The struct "payload" is used to Encrypt and Decrypt data based on a KMS key
type payload struct {
	Key     []byte
	Nonce   *[nonceLength]byte
	Message []byte
}

// Function to convert float64 to string and send the data encrypted
func SendEncryptedFloat(ID string, name string, value float64, kmsClient *kms.KMS) {

	r := strings.NewReader(strconv.FormatFloat(value, 'E', -1, 32))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}
	
	encrypted, err := Encrypt(kmsClient, plaintext)
	if err != nil {
		panic(err)
	}

	filter := bson.D{primitive.E{Key: "id", Value: ID}}

	update := bson.D{primitive.E{Key: "$set", Value: bson.D{
		primitive.E{Key: name, Value: encrypted},
	}}}

	collection.FindOneAndUpdate(ctx, filter, update)

}

// Function to convert bool to string and send the data encrypted
func SendEncryptedBool(ID string, name string, value bool, kmsClient *kms.KMS) {

	r := strings.NewReader(strconv.FormatBool(value))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}
	
	encrypted, err := Encrypt(kmsClient, plaintext)
	if err != nil {
		panic(err)
	}

	filter := bson.D{primitive.E{Key: "id", Value: ID}}

	update := bson.D{primitive.E{Key: "$set", Value: bson.D{
		primitive.E{Key: name, Value: encrypted},
	}}}

	collection.FindOneAndUpdate(ctx, filter, update)

}

// Function to convert int to string and send the data encrypted
func SendEncryptedInt(ID string, name string, value int, kmsClient *kms.KMS) {

	r := strings.NewReader(strconv.Itoa(value))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}
	
	encrypted, err := Encrypt(kmsClient, plaintext)
	if err != nil {
		panic(err)
	}

	filter := bson.D{primitive.E{Key: "id", Value: ID}}

	update := bson.D{primitive.E{Key: "$set", Value: bson.D{
		primitive.E{Key: name, Value: encrypted},
	}}}

	collection.FindOneAndUpdate(ctx, filter, update)

}

// Function to convert int64 to string and send the data encrypted
func SendEncryptedInt64(ID string, name string, value int64, kmsClient *kms.KMS) {

	r := strings.NewReader(string(value))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}
	
	encrypted, err := Encrypt(kmsClient, plaintext)
	if err != nil {
		panic(err)
	}

	filter := bson.D{primitive.E{Key: "id", Value: ID}}

	update := bson.D{primitive.E{Key: "$set", Value: bson.D{
		primitive.E{Key: name, Value: encrypted},
	}}}

	collection.FindOneAndUpdate(ctx, filter, update)

}

// Sending a string data encrypted
func SendEncryptedString(ID string, name string, value string, kmsClient *kms.KMS) {

	r := strings.NewReader(value)
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}
	
	encrypted, err := Encrypt(kmsClient, plaintext) // <-- to be implemented
	if err != nil {
		panic(err)
	}

	filter := bson.D{primitive.E{Key: "id", Value: ID}}

	update := bson.D{primitive.E{Key: "$set", Value: bson.D{
		primitive.E{Key: name, Value: encrypted},
	}}}

	collection.FindOneAndUpdate(ctx, filter, update)

}

// Function to send the data encrypted -> *time.Time or time.Time need the conversion to string before
func SendEncryptedStringData(ID string, name string, value string, kmsClient *kms.KMS) {

	r := strings.NewReader(value)
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}
	
	encrypted, err := Encrypt(kmsClient, plaintext)
	if err != nil {
		panic(err)
	}

	filter := bson.D{primitive.E{Key: "id", Value: ID}}

	update := bson.D{primitive.E{Key: "$set", Value: bson.D{
		primitive.E{Key: name, Value: encrypted},
	}}}

	collection.FindOneAndUpdate(ctx, filter, update)

}

// Function receive encrypted string and decrypt it
func ReceiveAndDecryptString(value []byte, kmsClient *kms.KMS) (string){

	r := strings.NewReader(string(value))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}

	decrypted, _ := Decrypt(kmsClient, plaintext)
	if err != nil {
		panic(err)
	}

	return string(decrypted)

}

// Function receive encrypted string and decrypt it converting to float64
func ReceiveAndDecryptFloat(value []byte, kmsClient *kms.KMS) (float64){

	r := strings.NewReader(string(value))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}

	decrypted, _ := Decrypt(kmsClient, plaintext) // <-- to be implemented
	if err != nil {
		panic(err)
	}

	newValue, _ := strconv.ParseFloat(string(decrypted), 64)

	return newValue

}

// Function receive encrypted string and decrypt it converting to int
func ReceiveAndDecryptInt(value []byte, kmsClient *kms.KMS) (int){

	r := strings.NewReader(string(value))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}

	decrypted, _ := Decrypt(kmsClient, plaintext) // <-- to be implemented
	if err != nil {
		panic(err)
	}

	newValue, err := strconv.ParseInt(string(decrypted), 10, 64)

	finalValue := int(newValue)

	return finalValue

}

// Function receive encrypted string and decrypt it converting to int64
func ReceiveAndDecryptFloatToInt64(value []byte, kmsClient *kms.KMS) (int64){

	r := strings.NewReader(string(value))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}

	decrypted, _ := Decrypt(kmsClient, plaintext) // <-- to be implemented
	if err != nil {
		panic(err)
	}	

	floatValue, _ := strconv.ParseFloat(string(decrypted), 64)

	newValue :=  int64(floatValue)

	return newValue

}

// Function receive encrypted string and decrypt it converting to bool
func ReceiveAndDecryptBool(value []byte, kmsClient *kms.KMS) (bool){

	r := strings.NewReader(string(value))
	plaintext, err := ioutil.ReadAll(r)

	if err != nil {
		panic(err)
	}

	decrypted, _ := Decrypt(kmsClient, plaintext) // <-- to be implemented
	if err != nil {
		panic(err)
	}

	newValue, err := strconv.ParseBool(string(decrypted))

	return newValue

}

// Encrypting data with AWS KMS
func Encrypt(kmsClient *kms.KMS, plaintext []byte) ([]byte, error) {
	
	// KMS key
	keyId := kmsKeyName
	// Putting a typ for the key from KMS
	keySpec := "RSA_4096"
	// Generating a key input based on KMS too
	dataKeyInput := kms.GenerateDataKeyInput{KeyId: &keyId, KeySpec: &keySpec}

	// Generating a key output based on key input
	dataKeyOutput, err := kmsClient.GenerateDataKey(&dataKeyInput)
	if err == nil {
		fmt.Println(dataKeyOutput)
	} else {
		fmt.Println("error: ", err)
	}

	p := &payload{
		Key:   dataKeyOutput.CiphertextBlob,
		Nonce: &[nonceLength]byte{},
	}

	if _, err = rand.Read(p.Nonce[:]); err != nil {
		return nil, err
	}

	key := &[keyLength]byte{}
	copy(key[:], dataKeyOutput.Plaintext)

	p.Message = secretbox.Seal(p.Message, plaintext, p.Nonce, key)

	buf := &bytes.Buffer{}
	if err := gob.NewEncoder(buf).Encode(p); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil

}

// Decrypting data with AWS KMS
func Decrypt(kmsClient *kms.KMS, ciphertext []byte) ([]byte, error) {

	var p payload
	gob.NewDecoder(bytes.NewReader(ciphertext)).Decode(&p)

	dataKeyOutput, err := kmsClient.Decrypt(&kms.DecryptInput{
		CiphertextBlob: p.Key,
	})
	if err == nil {
		fmt.Println(dataKeyOutput)
	} else {
		fmt.Println("error: ", err)
	}

	key := &[keyLength]byte{}
	copy(key[:], dataKeyOutput.Plaintext)

	var plaintext []byte
	plaintext, ok := secretbox.Open(plaintext, p.Message, p.Nonce, key)
	if !ok {
		return nil, fmt.Errorf("Failed to open secretbox")
	}
	return plaintext, nil

}
