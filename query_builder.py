import random
import struct


# DNS Query Structure: https://learn.microsoft.com/en-us/windows-server/networking/dns/message-formats
class Query:
    def __init__(self, header, question):
        if not isinstance(header, Header):
            raise TypeError(f"header must be of Header type. Currently {type(header)}")

        if not isinstance(question, Question):
            raise TypeError(
                f"question must be of Question type. Currently {type(question)}"
            )

        self.header = header
        self.question = question

    # building query, we only need flag for request and recursion desired.
    def buildingQuery(self):
        header = self.header.buildHeader()
        question = self.question.buildQuestion()
        return header + question

# Header Class: takes in flag and counts class object.
class Header:
    def __init__(self, flag, counts):
        if not isinstance(flag, Flag):
            raise TypeError(f"flag must be of Flag type. Currently {type(flag)}")

        if not isinstance(counts, Counts):
            raise TypeError(f"counts must be of Counts type. Currently {type(counts)}")

        self.transactionID = random.getrandbits(
            16
        )  # transaction ID is randomly generated 16 bits
        self.flag = flag
        self.counts = counts

        if not 0 <= self.transactionID <= 0xFFFF:
            raise ValueError(
                f"transaction ID should be in 16 bits. Currently {self.transactionID:b}"
            )

    # build header and return 12 bytes DNS header.
    def buildHeader(self):
        flagBytes = self.flag.buildingFlag()
        questionCount = self.counts.get_questionCount()
        answerCount = self.counts.get_answerCount()
        authorityResourceCount = self.counts.get_authorityResourceCount()
        additionalResourceCount = self.counts.get_additionalResourceCount()

        header = struct.pack(
            ">6H",  # big endian, unsigned integer
            self.transactionID,
            flagBytes,
            questionCount,
            answerCount,
            authorityResourceCount,
            additionalResourceCount,
        )
        if len(header) != 12:
            raise ValueError(f"header should be 12 bytes. Currently {len(header)}")

        print(bytes(header))
        return header

    # get_transactionID: return transactionID
    def get_transactionID(self):
        return self.transactionID


# Question class
# Takes in questionname (str), questiontype (type),
# questionClass (2 bytes / 16 bits) defaulted to 0x0001
# Supporting question type:
#   1. A
#   2. AAAA
#   3. NS
#   4. PTR
#   5. MX
#   6. SRV
#   7. SRV
#   8. IXFR
#   9. AXFR
#   10. All (All records)
class Question:
    def __init__(self, questionName, questionType, questionClass=0x0001):
        if not isinstance(questionName, str):
            raise TypeError(
                f"questionName should be string. Currently {type(questionName)}"
            )

        if not isinstance(questionType, str):
            raise TypeError(
                f"questionType should be string. Currently {type(questionType)}"
            )

        if not isinstance(questionClass, int):
            raise TypeError(
                f"questionClass should be int. Currently {type(questionClass)}"
            )

        if not 0 <= questionClass <= 0xFFFF:
            raise ValueError(
                f"questionClass should be 2 bytes. Currently {questionClass}"
            )

        questionType = questionType.upper()
        question_type = {
            "A",
            "AAAA",
            "NS",
            "CNAME",
            "PTR",
            "MX",
            "SRV",
            "IXFR",
            "AXFR",
            "ALL",
        }

        if questionType not in question_type:
            raise ValueError(
                f"questionType must be a valid question type. Currently {questionType}"
            )

        self.questionName = questionName
        self.questionType = questionType
        self.questionClass = struct.pack(">H", questionClass)

    # using questionType, convert it to the corresponding byte
    def encodeQuestionType(self):
        questionType = {
            "A": 0x01,
            "AAAA": 0x1C,
            "NS": 0x02,
            "CNAME": 0x05,
            "PTR": 0x0C,
            "MX": 0x0F,
            "SRV": 0x21,
            "IXFR": 0xFB,
            "AXFR": 0xFC,
            "ALL": 0xFF,
        }

        questionTypeByte = questionType.get(self.questionType, None)
        if questionTypeByte is None:
            raise ValueError(
                f"The following question type is not supported. questionType: {self.questionType}"
            )

        # struct.pack ensures that returning value is bytes not integer.
        return struct.pack(">H", questionTypeByte)

    # return domain name being queried
    # DNS domain names are expressed as a series of lables (e.g., microsoft.com).
    # In the Question Name field, the domain name is encoded as a series of length-value pairs: a 1-byte field indicating the length of the label,
    # followed by the label itself. For example, microsoft.com is encoded as 0x09microsoft0x03com0x00, where the hexadecimal digits
    # represent label lengths, the ASCII characters are the labels, and the final 0 indicates the end of the name.
    # name must be between 0 and 255 bytes. and each subset of name must be between 1 and 63 bytes  (DNS standard)
    def encodeQuestionName(self):
        encodedNameLst = []
        nameLst = self.questionName.split(".")

        for subname in nameLst:
            if not 1 <= len(subname) <= 63:
                raise ValueError(f"subname should be between 1 and 63 bytes. Subname: {subname} length: {len(subname)}")
        
            lengthByte = bytes([len(subname)])  # how many bytes for each subset of name
            subnameASCII = subname.encode("ascii")  # translate into ASCII
            encodedNameLst.append(lengthByte)
            encodedNameLst.append(subnameASCII)

        encodedNameLst.append(bytes([0]))
        encodedName = b"".join(encodedNameLst)

        if not 0 <= len(encodedName) <= 255:
            raise ValueError("encoded name should be less than 256 bytes")

        print(f"this is encodedName {encodedName}")
        return encodedName

    def buildQuestion(self):
        questionType = self.encodeQuestionType()
        questionName = self.encodeQuestionName()

        encodedQuestion = questionName + questionType + self.questionClass
        print(f"this is encodedQuestion: {encodedQuestion}")
        return encodedQuestion


# Flags (16 bits):
#   Request / Response: 1-bit field set to 0 for a request / 1 for a response.
#   Operation code: 4-bit field representing the name server operation of the packet, 0x0 is a query
#   Authoritative answer: 1-bit field indicating the responder is authoritative for the queried domain name.
#   Truncation: 1-bit field set to 1 if the total number of response exceeded the UDP datagram size. Unless UDP datagrams larger than 512 bytes of EDNS0 are enabled, only the first 512 bytes of the UDP reply are returned.
#   Recursion desired: 1-bit field set to 1 for a recursive query and 0 for iterative queries. If set to 0, the DNS server returns a list of other DNS servers from local cache data.
#   Recursion available: 1-bit field set by a DNS server to 1 if it can handle recursive queries. If recursion is disabled, the server sets the field appropraitely.
#   Reserved: 3-bit field that is reserved and set to 0.
#   Return code: 4 bit field holding the return code:
#       0: Successful response (query answer is in the response)
#       0x3: Name error, indicating that an authoritative DNS server responded that the domain name does not exist.
# constructors are in bits
class Flag:
    def __init__(
        self,
        Request,
        OPCODE,
        AuthoritativeAnswer,
        Truncation,
        RecursionDesired,
        RecursionAvailable,
        Reserved,
        ReturnCode,
    ):

        self.request = Request
        self.opcode = OPCODE
        self.authoritativeAnswer = AuthoritativeAnswer
        self.truncation = Truncation
        self.recursionDesired = RecursionDesired
        self.recursionAvailable = RecursionAvailable
        self.reserved = Reserved
        self.returnCode = ReturnCode

        if not 0 <= self.request <= 0b1:
            raise ValueError(f"request should be one bit. Currently {self.request:b}")
        if not 0 <= self.opcode <= 0b1111:
            raise ValueError(f"opcode should be four bits Currently {self.opcode:b}")
        if not 0 <= self.authoritativeAnswer <= 0b1:
            raise ValueError(
                f"authoritativeAnswer should be one bit. Currently {self.authoritativeAnswer:b}"
            )
        if not 0 <= self.truncation <= 0b1:
            raise ValueError(
                f"truncation should be one bit. Currently {self.truncation:b}"
            )
        if not 0 <= self.recursionDesired <= 0b1:
            raise ValueError(
                f"recursionDesired should be one bit. Currently {self.recursionDesired:b}"
            )
        if not 0 <= self.recursionAvailable <= 0b1:
            raise ValueError(
                f"recursionAvailable should be one bit. Currently {self.recursionAvailable:b}"
            )
        if not 0 <= self.reserved <= 0b111:
            raise ValueError(
                f"reserved should be three bits. Currently {self.reserved:b}"
            )
        if not 0 <= self.returnCode <= 0b1111:
            raise ValueError(
                f"returnCode should be four bits. Currently {self.returnCode:b}"
            )

        self.flags = (
            self.request << 15
            | self.opcode << 11
            | self.authoritativeAnswer << 10
            | self.truncation << 9
            | self.recursionDesired << 8
            | self.recursionAvailable << 7
            | self.reserved << 4
            | self.returnCode
        )

        if not 0 <= self.flags <= 0xFFFF:
            raise ValueError(f"flag should be 16 bits. Currently {self.flags:b}")

    # return 16 bits flags
    def buildingFlag(self):
        print(f"this is the flag {self.flags:b}, bit length: {self.flags.bit_length()}")
        return self.flags



# contains question count, answer count, authority resource count, additional resource count.
# All of the counts are in 16 bits (2 bytes)
class Counts:
    def __init__(
        self,
        questionCount,
        answerCount,
        authorityResourceCount,
        additionalResourceCount,
    ):

        # query allows upto 1 question
        if not 0 <= questionCount <= 1:
            raise ValueError(
                f"questionCount should not be bigger than one. Currently {questionCount:b}"
            )

        if not 0 <= answerCount <= 0xFFFF:
            raise ValueError(
                f"answer count should be in 16 bits. Currently {answerCount:b}"
            )

        if not 0 <= authorityResourceCount <= 0xFFFF:
            raise ValueError(
                f"authority resource count should be in 16 bits. Currently {authorityResourceCount:b}"
            )

        if not 0 <= additionalResourceCount <= 0xFFFF:
            raise ValueError(
                f"additional resource count should be in 16 bits. Currently {additionalResourceCount:b}"
            )

        self.questionCount = questionCount
        self.answerCount = answerCount
        self.authorityResourceCount = authorityResourceCount
        self.additionalResourceCount = additionalResourceCount

    def get_questionCount(self):
        return self.questionCount

    def get_answerCount(self):
        return self.answerCount

    def get_authorityResourceCount(self):
        return self.authorityResourceCount

    def get_additionalResourceCount(self):
        return self.additionalResourceCount


def main():
    flag = Flag(0b1, 0b1010, 0b1, 0b0, 0b1, 0b1, 0b110, 0b1101)
    counts = Counts(1, 10, 10, 10)
    header = Header(flag, counts)
    header.buildHeader()

    question = Question("microsoft.com", "A")
    question.buildQuestion()


if __name__ == "__main__":
    main()
