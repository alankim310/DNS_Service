# child class of Query specifically designed for question query.
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

from query_builder import *

class questionQuery(Query):
    def __init__(self, questionName, questionType, questionClass=0x0001):
        # besides question count of 1, answer count, authority resource count, additional resource count will always be 0.
        counts = Counts(
            questionCount=1,
            answerCount=0,
            authorityResourceCount=0,
            additionalResourceCount=0,
        )

        flag = Flag(
            Request = 0,
            OPCODE = 0b0000,
            AuthoritativeAnswer=0,
            Truncation = 0,
            RecursionDesired= 1, #needed to be recursive query
            RecursionAvailable= 0,
            Reserved = 0b000,
            ReturnCode= 0b0000
        )

        question = Question(
            questionName=questionName,
            questionType = questionType,
            questionClass=questionClass,
        )

        header = Header(flag, counts)

        super().__init__(
            header = header,
            question = question
        )

    #return question query in bytes
    def buildingQuery(self):
        return super().buildingQuery()

def main():
    question = questionQuery("www.microsoft.com", "AAAA")
    print(question.buildingQuery())

if __name__ == "__main__":
    main()