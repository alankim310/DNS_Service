
# validateType: Given variable, expected Type (such as int, or str) and variable Name,
# Check whether variable is of the expected Type. If not, return error. 
def validateType(variable, expectedType, variableName):
    if not isinstance(variable, expectedType):
        raise TypeError(f"{variableName} needs to be {expectedType.__name__} object. "
                        f"Currently {type(variable).__name__}.")

# validateRangeByte: Given variable, variableName, min, max, raise value Error if variable is not of range of length of bytes
def validateRangeByte(variable, variableName, minNum = None, maxNum = None):
    if minNum is not None:
        if not len(variable) >= minNum:
            raise ValueError(f"{variableName} should be greater or equal to min {minNum}. Current length: {len(variable)}")
    if maxNum is not None:
        if not len(variable) <= maxNum:
            raise ValueError(f"{variableName} should be less than or equal to max {maxNum}. Current length: {len(variable)}")

#validateExactByte: Given variable, variableName, and exactLength, raise value Error if variable length does not equal to exactLength. 
def validateExactByte(variable, variableName, exactLength):
    if not len(variable) == exactLength:
        raise ValueError(f"{variableName} should be of length {exactLength}. Current length: {len(variable)}")

# raiseValueError_None: Given variable and variable Name raise Value Error if variable is None
def raiseValueError_None(variable, variableName):
    if variable is None:
        raise ValueError(f"{variableName} should not be None. Invalid value.")

def main():
    print("validation.py should not be run by itself")

if __name__ == "__main__":
    main()