class HtmlTable():
    """ """
    def __init__(self, attributes=''):
        """ """
        self._table = '<table {0}>'.format(attributes)

    def tr(self, attributes=''):
        """ """
        # new table
        if len(self._table) != 0:
            self._table += '</tr>'
        self._table += '<tr {0}>'.format(attributes)

    def th(self, data, attributes=''):
        """ """
        self._table += '<th {0}>{1}</th>'.format(attributes, str(data))

    def td(self, data, attributes=''):
        """ """
        self._table += '<th {0}>{1}</th>'.format(attributes, str(data))

    def __str__(self):
        """ """
        self._table += '</tr></table>'
        self._table += '</table>'
        return self._table
