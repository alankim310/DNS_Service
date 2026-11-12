import struct
from validation import *
import json

# DNS Parser is used for both decoded representation for the client as well as raw representation for local recursive resolver.
# What client will see:

# Currently only support A, AAAA, and CNAME

# Header
# Transaction ID (in hex)
# Counts
#   Question, Answer, Authority, Additional

# QUESTION
# QName (Question Name): "example.com"
# Question Type: "A"
# Question Class: "IN"


# Answer
# Response Name: www.microsoft.com-c-3.edgekey.net
# Response Type: CNAME
# Response Class: "IN"
# TTL: 300
# Response RDATA: "93.184.215.14"
class DNSParser:
    def __init__(self, rawByteData):
        validateType(rawByteData, bytes, "rawByteData in DNSParser")
        self.data = rawByteData
        self.transaction = TransactionParser(self.data).TransactionHex
        self.counts = CountsParser(self.data).countsDict
        self.questions, questionLastIndex = self.retrievingQuestions()
        self.answers, answerLastIndex = self.retrievingAnswers(
            "answer", questionLastIndex + 1
        )
        self.authorities, authoritiesLastIndex = self.retrievingAnswers(
            "authority", answerLastIndex + 1
        )
        self.additionals, _ = self.retrievingAnswers(
            "additional", authoritiesLastIndex + 1
        )

        self.parsedJson = self.parseDNSQuery()

    # return parsed query in JSON
    def parseDNSQuery(self):
        # using self.questions, return list of questions where each element represents a question that contains Qname, question type and question class
        def parseQuestions():
            lst = []
            for question in self.questions:
                questionData = {
                    "questionName": question.decodedName,
                    "questionType": question.recordType,
                    "questionClass": question.recordClass,
                }
                lst.append(questionData)
            return lst

        # return list of answers where each element represent response name, response type, response class, TTL, resposne RD, and response data
        # because answer, authority, and additional information use the same structure, we will distinguish the section with section name in the same function.
        # available section: "answer", "authority", "additional"
        def parseAnswers(section):
            lst = []
            answers = None

            if section == "answer":
                answers = self.answers
            elif section == "authority":
                answers = self.authorities
            elif section == "additional":
                answers = self.additionals

            if answers is None:
                raise ValueError(
                    f"wrong section input in parseAnswers. currently {section}"
                )

            for answer in answers:
                answerData = {
                    "ResponseName": answer.decodedName,
                    "ResponseType": answer.recordType,
                    "ResponseClass": answer.recordClass,
                    "TTL": answer.ttl,
                    "ResponseResourceDataLength": answer.resourceDataLength,
                    "ResponseData": answer.resourceData,
                }
                lst.append(answerData)
            return lst

        questionData = parseQuestions()
        answerData = parseAnswers("answer")
        authorityData = parseAnswers("authority")
        additionalData = parseAnswers("additional")

        data = {
            "Header": {
                "TransactionID": self.transaction,
                "Counts": self.counts,
            },
            "Questions": questionData,
            "Answers": answerData,
            "Authorities": authorityData,
            "Additionals": additionalData,
        }

        parsedJson = json.dumps(data, indent=4)
        return parsedJson

    # There could be multiple question according to the counts. Therefore, retrieve all questions.
    def retrievingQuestions(self):
        questionLst = []
        questionCount = self.counts.get("question", None)
        raiseValueError_None(questionCount, "questionCount")
        validateType(questionCount, int, "questionCount")
        index = 11  # question bytes start from 12, but we are trying to get the last index of each question
        for _ in range(questionCount):
            question = QuestionParser(self.data, index + 1)
            questionLst.append(question)
            index = question.lastIndex

        return (questionLst, index)

    # There could be multiple answers to the section. Also, since answer, authority, and additional information have the same structure,
    # we will use sectionName to distinguish between them, and firstIndex of each section
    def retrievingAnswers(self, sectionName, firstIndex):
        answerLst = []
        answerCount = self.counts.get(sectionName, None)
        raiseValueError_None(answerCount, f"{sectionName} in retrievingAnswers")
        validateType(answerCount, int, f"{sectionName} in retrievingAnswers")
        index = (
            firstIndex - 1
        )  # Subtracting one because we are trying to get we are trying to get the last index of each question.
        for _ in range(answerCount):
            answer = AnswerParser(self.data, index + 1)
            answerLst.append(answer)
            index = answer.lastIndex

        return (answerLst, index)


# retreiving transaction id, question name, question type
class QuestionParser:
    def __init__(self, rawByteData, startIndex):
        validateType(rawByteData, bytes, "rawByteData in QuestionParser")
        validateType(startIndex, int, "startIndex in QuestionParser")
        self.data = rawByteData
        self.startIndex = startIndex
        self.questionNameParser = NameParser(self.data, self.startIndex)
        questionNameLastIndex = self.questionNameParser.LastIndex
        self.decodedName = self.questionNameParser.decodedName
        self.recordType = TypeParser(self.data, questionNameLastIndex + 1).Type
        self.recordClass = ClassParser(self.data, questionNameLastIndex + 3).recordClass
        self.lastIndex = questionNameLastIndex + 4


# retrieving class
class ClassParser:
    def __init__(self, rawByteData, startIndex):
        validateType(rawByteData, bytes, "rawByteData in ClassParser")
        validateRangeByte(
            rawByteData, "rawByteData in ClassParser", minNum=startIndex + 2
        )
        self.data = rawByteData[startIndex : startIndex + 2]
        self.recordClass = self.retrieveRecordclass()

    def retrieveRecordclass(self):
        recordClassDict = {
            0x0001: "IN",
            0x0003: "CH",
            0x0004: "HS",
            0x00FE: "NONE",
            0x00FF: "ANY",
        }
        int_data = int.from_bytes(self.data, byteorder="big")
        recordClass = recordClassDict.get(int_data, None)
        raiseValueError_None(recordClass, "recordClass")
        return recordClass


# Retrieve Question Type
class TypeParser:
    def __init__(self, rawByteData, startIndex):
        validateType(rawByteData, bytes, "rawByteData in TypeParser")
        validateRangeByte(
            rawByteData, "rawByteData in TypeParser", minNum=startIndex + 2
        )
        self.data = rawByteData[startIndex : startIndex + 2]
        self.Type = self.retrieveType()

    def retrieveType(self):
        TypeDict = {
            0x01: "A",
            0x02: "NS",
            0x05: "CNAME",
            0x0C: "PTR",
            0x0F: "MX",
            0x21: "SRV",
            0xFB: "IXFR",
            0xFC: "AXFR",
            0xFF: "All",
            0x1C: "AAAA",
        }

        int_data = int.from_bytes(self.data, byteorder="big")
        Type = TypeDict.get(int_data, None)
        raiseValueError_None(Type, "Type")
        return Type


# retrieving decoded name and question name's last index
# For each of the byte, check the first 2 bits. Cases for the first 2 bits:
# 1. 00: Ordinary DNS label length
# 2. 01: Reserved for other / extended label formats
# 3. 10: Reserved
# 4. 11: DNS compression pointer


# we will support 00 and 11, and raise value error if 01, 10.
class NameParser:
    def __init__(self, rawByteData, startIndex):
        validateType(rawByteData, bytes, "rawByteData in NameParser")
        validateType(startIndex, int, "startIndex in NameParser")
        self.data = rawByteData
        self.startIndex = startIndex
        self.decodedName, self.LastIndex = self.retrieveDecodedName_and_LastIndex(
            self.startIndex
        )
        validateType(self.decodedName, str, "decodedName in NameParser")
        validateType(self.LastIndex, int, "LastIndex in NameParser")

    # getFirstTwoBits: given index (int), return the first two bits (integer) if 00 or 11.
    # raise value Error if 01 or 10
    def getFirstTwoBits(self, index):
        byte_Int = self.data[index]
        byte_Int = (byte_Int >> 6) & 0b11
        if byte_Int == 0b01 or byte_Int == 0b10:
            raise ValueError(f"Unsupported Name Type: Currently {byte_Int:2b}")
        return byte_Int

    # using rawByteData, decode the question name, and return string value of decoded name and last index as tuple
    # IF the first Two bits is 0b11, then, it retrieves from the pointed offset.
    def retrieveDecodedName_and_LastIndex(self, startIndex):
        index = startIndex
        DecodedNameLst = []
        while True:
            if self.data[index] == 0x00:
                break
            firstTwoBits = self.getFirstTwoBits(index)

            if firstTwoBits == 0b00:
                length = self.data[index]
                DecodedNameLst.append(
                    self.data[index + 1 : index + 1 + length].decode()
                )
                index = index + 1 + length
            elif firstTwoBits == 0b11:
                offset = (self.data[index] & 0x3F) << 8 | self.data[index + 1]
                index = index + 1
                DecodedNameLst.append(self.retrieveDecodedName_and_LastIndex(offset)[0])
                break

        return (".".join(DecodedNameLst), index)


# Retrieving Transaction ID
class TransactionParser:
    def __init__(self, rawByteData):
        validateType(rawByteData, bytes, "rawByteData in TransactionParser")
        validateRangeByte(rawByteData, "rawByteData in TransactionParser", minNum=2)

        self.TransactionByte = rawByteData[0:2]
        validateExactByte(
            self.TransactionByte, "TransactionByte in TransactionParser", 2
        )

        self.TransactionHex = self.ComputeTransactionHex(self.TransactionByte)

    # unpack Transaction Byte and return an hex value of the unpacked Byte
    def ComputeTransactionHex(self, TransactionByte):
        unpackedByte = struct.unpack("!H", TransactionByte)[0]
        return hex(unpackedByte)


# Retrieving counts for question, answer, authority, and additional
class CountsParser:
    def __init__(self, rawByteData):
        validateType(rawByteData, bytes, "rawByteData in RecordCount")
        self.data = rawByteData
        self.QuestionCountByte = rawByteData[4:6]
        self.AnswerCountByte = rawByteData[6:8]
        self.AuthorityCountByte = rawByteData[8:10]
        self.AdditionalCountByte = rawByteData[10:12]
        validateExactByte(self.QuestionCountByte, "QuestionCountByte", 2)
        validateExactByte(self.AnswerCountByte, "AnswerCountByte", 2)
        validateExactByte(self.AuthorityCountByte, "AuthorityCountByte", 2)
        validateExactByte(self.AdditionalCountByte, "AdditionalCountByte", 2)
        self.countsDict = self.countsDictionary()
        validateType(self.countsDict, dict, "countsDict in countsParser")

    # return dictionary of the following that contains question resource record count, answer resource record count, authority resource record count, and additional resource record count
    def countsDictionary(self):
        questionCount = struct.unpack("!H", self.QuestionCountByte)[0]
        answerCount = struct.unpack("!H", self.AnswerCountByte)[0]
        authorityCount = struct.unpack("!H", self.AuthorityCountByte)[0]
        additionalCount = struct.unpack("!H", self.AdditionalCountByte)[0]

        return {
            "question": questionCount,
            "answer": answerCount,
            "authority": authorityCount,
            "additional": additionalCount,
        }


# retrieve recordname, record type, recrod class, timne to live, data length, and resource data
# for answer, authority, additional information
class AnswerParser:
    def __init__(self, rawByteData, firstIndex):
        validateType(rawByteData, bytes, "rawByteData in AnswerParser")
        validateType(firstIndex, int, "firstIndex in AnswerParser")
        self.data = rawByteData
        self.firstIndex = firstIndex
        self.answerNameParser = NameParser(self.data, self.firstIndex)
        self.decodedName = self.answerNameParser.decodedName

        index = self.answerNameParser.LastIndex + 1

        self.recordType = TypeParser(self.data, index).Type
        index += 2

        self.recordClass = ClassParser(self.data, index).recordClass
        index += 2

        self.ttl = struct.unpack("!I", self.data[index : index + 4])[0]
        index += 4

        self.resourceDataLength = struct.unpack("!H", self.data[index : index + 2])[0]
        index += 2

        resourceDataClass = ResourceData(self.data, index, self.recordType)
        self.resourceData = resourceDataClass.resourceData
        self.lastIndex = resourceDataClass.lastIndex


# retrieve resource Data. Currently support A, AAAA, and CNAME
class ResourceData:
    def __init__(self, rawByteData, firstIndex, type):
        validateType(rawByteData, bytes, "rawByteData in ResourceData")
        validateType(firstIndex, int, "firstIndex in ResourceData")
        validateType(type, str, "type in ResourceData")
        self.data = rawByteData
        self.firstIndex = firstIndex
        self.type = type
        getResourceDataResult = self.getResourceData()
        self.resourceData = getResourceDataResult[0]
        self.lastIndex = getResourceDataResult[1]

    # get resource data and last index in int
    def getResourceData(self):
        if self.type == "A":  # IPv4
            IPv4AddressLst = list(
                struct.unpack("!4B", self.data[self.firstIndex : self.firstIndex + 4])
            )
            IPv4Address = ".".join(str(n) for n in IPv4AddressLst)
            return (IPv4Address, self.firstIndex + 3)

        elif self.type == "AAAA":  # IPv6 There are 8 addresses of 2 bytes
            IPv6AddressLst = list(
                struct.unpack("!8H", self.data[self.firstIndex : self.firstIndex + 16])
            )
            IPv6Address = ":".join(f"{n:x}" for n in IPv6AddressLst)
            return (IPv6Address, self.firstIndex + 15)

        elif self.type == "CNAME":
            return NameParser(
                self.data, self.firstIndex
            ).retrieveDecodedName_and_LastIndex(self.firstIndex)

        else:
            raise ValueError(f"Unsupported Type. Currently {self.type}")


def main():
    mockResult = DNSParser(
        b" \x85\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x03www\tmicrosoft\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x0c\x94\x00#\x03www\tmicrosoft\x07com-c-3\x07edgekey\x03net\x00\xc0/\x00\x05\x00\x01\x00\x00\x01e\x00\x19\x06e13678\x04dscb\nakamaiedge\xc0M\xc0^\x00\x01\x00\x01\x00\x00\x00\x14\x00\x04\x17\x0c\x03\xd0"
    )


if __name__ == "__main__":
    main()
