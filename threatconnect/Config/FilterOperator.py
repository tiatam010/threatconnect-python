""" standard """
import operator

""" third-party """
from enum import Enum


class FilterOperator(Enum):
    """ """
    # Query Operator
    EQ = operator.eq
    NE = operator.ne
    GT = operator.gt
    GE = operator.ge
    LT = operator.lt
    LE = operator.le
