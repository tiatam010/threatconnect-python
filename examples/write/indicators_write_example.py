""" standard """
import sys

""" custom """
from examples.working_init import *

enable_example1 = True


def main():
    """ """

    if enable_example1:
        """ """
        indicators = tc.indicators()
        # indicator = indicators.add_indicator('bcs@aol.com')
        # indicator = indicators.add_indicator('4.3.2.1')
        # indicator = indicators.add_indicator('ac11ba81f1dc6d3637589ffa04366599')
        indicator = indicators.add_indicator('www.bcs.com')
        indicator.set_confidence(90)
        indicator.set_rating('2.0')
        indicators.send()

        for indi in indicators:
            print(indi)
            pd('id', indi.get_id())

        indicator = indicators.add_indicator('4.3.2.1')
        indicator.set_confidence(60)
        indicator.set_rating('4.0')
        indicators.send()

        for indi in indicators:
            print(indi)
            pd('id', indi.get_id())

if __name__ == "__main__":
    main()
