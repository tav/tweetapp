"""
An exception formatter that shows traceback supplements and traceback info.

  >>> try:
  ...     1/0
  ... except:
  ...     print print_exception()
  Traceback (most recent call last):
    Module error/traceback, line 2, in ?
  ZeroDivisionError: integer division or modulo by zero
  <BLANKLINE>

  >>> try:
  ...     1/0
  ... except:
  ...     print print_exception(stream=sys.stdout)
  Traceback (most recent call last):
    Module error/traceback, line 2, in ?
  ZeroDivisionError: integer division or modulo by zero
  <BLANKLINE>

Output could be optionally rendered in HTML too:

  >>> try:        # doctest: +NORMALIZE_WHITESPACE
  ...     1/0
  ... except:
  ...     print print_exception(as_html=True)
  <p>Traceback (most recent call last):
  <ul>
  <li>  Module error/traceback, line 2, in ?</li>
  </ul>ZeroDivisionError: integer division or modulo by zero<br />
  </p>

"""

import sys
import cgi
import linecache
import traceback

# ------------------------------------------------------------------------------
# some konstants
# ------------------------------------------------------------------------------

__metaclass__ = type

DEBUG_EXCEPTION_FORMATTER = 1

LIMIT = 200

if hasattr(sys, 'tracebacklimit'):
    LIMIT = min(LIMIT, sys.tracebacklimit)

# ------------------------------------------------------------------------------
# the klasses that do the actual formatting
# ------------------------------------------------------------------------------

class TextExceptionFormatter:

    line_sep = '\n'
    show_revisions = 0

    def __init__(self, limit=None, with_filenames=False):
        self.limit = limit
        self.with_filenames = with_filenames

    def escape(self, s):
        return s

    def getPrefix(self):
        return 'Traceback (most recent call last):'

    def getLimit(self):
        limit = self.limit
        if limit is None:
            limit = getattr(sys, 'tracebacklimit', 200)
        return limit

    def formatSupplementLine(self, line):
        return '   - %s' % line

    def formatSourceURL(self, url):
        return [self.formatSupplementLine(url)]

    def formatSupplement(self, supplement, tb):
        result = []
        fmtLine = self.formatSupplementLine

        url = getattr(supplement, 'source_url', None)
        if url is not None:
            result.extend(self.formatSourceURL(url))

        line = getattr(supplement, 'line', 0)
        if line == -1:
            line = tb.tb_lineno
        col = getattr(supplement, 'column', -1)
        if line:
            if col is not None and col >= 0:
                result.append(fmtLine('Line %s, Column %s' % (
                    line, col)))
            else:
                result.append(fmtLine('Line %s' % line))
        elif col is not None and col >= 0:
            result.append(fmtLine('Column %s' % col))

        expr = getattr(supplement, 'expression', None)
        if expr:
            result.append(fmtLine('Expression: %s' % expr))

        warnings = getattr(supplement, 'warnings', None)
        if warnings:
            for warning in warnings:
                result.append(fmtLine('Warning: %s' % warning))

        getInfo = getattr(supplement, 'getInfo', None)
        if getInfo is not None:
            try:
                extra = getInfo()
                if extra:
                    extra = self.escape(extra)
                    if self.line_sep != "\n":
                        extra = extra.replace(" ", "&nbsp;")
                        extra = extra.replace("\n", self.line_sep)
                    result.append(extra)
            except:
                if DEBUG_EXCEPTION_FORMATTER:
                    traceback.print_exc()
                # else just swallow the exception.
        return result

    def formatTracebackInfo(self, tbi):
        return self.formatSupplementLine('__traceback_info__: %s' % (tbi, ))

    def formatLine(self, tb):
        f = tb.tb_frame
        lineno = tb.tb_lineno
        co = f.f_code
        filename = co.co_filename
        name = co.co_name
        locals = f.f_locals
        globals = f.f_globals

        if self.with_filenames:
            s = '  File "%s", line %d' % (filename, lineno)
        else:
            modname = globals.get('__name__', filename)
            s = '  Module %s, line %d' % (modname, lineno)

        s = s + ', in %s' % name

        result = []
        result.append(self.escape(s))

        # Append the source line, if available
        line = linecache.getline(filename, lineno)
        if line:
            result.append("    " + self.escape(line.strip()))

        # Output a traceback supplement, if any.
        if '__traceback_supplement__' in locals:
            # Use the supplement defined in the function.
            tbs = locals['__traceback_supplement__']
        elif '__traceback_supplement__' in globals:
            # Use the supplement defined in the module.
            # This is used by Scripts (Python).
            tbs = globals['__traceback_supplement__']
        else:
            tbs = None
        if tbs is not None:
            factory = tbs[0]
            args = tbs[1:]
            try:
                supp = factory(*args)
                result.extend(self.formatSupplement(supp, tb))
            except:
                if DEBUG_EXCEPTION_FORMATTER:
                    traceback.print_exc()
                # else just swallow the exception.

        try:
            tbi = locals.get('__traceback_info__', None)
            if tbi is not None:
                result.append(self.formatTracebackInfo(tbi))
        except:
            if DEBUG_EXCEPTION_FORMATTER:
                traceback.print_exc()
            # else just swallow the exception.

        return self.line_sep.join(result)

    def formatExceptionOnly(self, etype, value):
        result = ''.join(traceback.format_exception_only(etype, value))
        return result.replace('\n', self.line_sep)

    def formatLastLine(self, exc_line):
        return self.escape(exc_line)

    def formatException(self, etype, value, tb):
        # The next line provides a way to detect recursion.
        __exception_formatter__ = 1
        result = [self.getPrefix() + '\n']
        limit = self.getLimit()
        n = 0
        while tb is not None and (limit is None or n < limit):
            if tb.tb_frame.f_locals.get('__exception_formatter__'):
                # Stop recursion.
                result.append('(Recursive formatException() stopped)\n')
                break
            line = self.formatLine(tb)
            result.append(line + '\n')
            tb = tb.tb_next
            n = n + 1
        exc_line = self.formatExceptionOnly(etype, value)
        result.append(self.formatLastLine(exc_line))
        return result

class HTMLExceptionFormatter(TextExceptionFormatter):

    line_sep = '<br />\r\n'

    def escape(self, s):
        return cgi.escape(s)

    def getPrefix(self):
        return '<p>Traceback (most recent call last):\r\n<ul>'

    def formatSupplementLine(self, line):
        return '<b>%s</b>' % self.escape(str(line))

    def formatTracebackInfo(self, tbi):
        s = self.escape(str(tbi))
        s = s.replace('\n', self.line_sep)
        return '__traceback_info__: %s' % (s, )

    def formatLine(self, tb):
        line = TextExceptionFormatter.formatLine(self, tb)
        return '<li>%s</li>' % line

    def formatLastLine(self, exc_line):
        return '</ul>%s</p>' % self.escape(exc_line).replace(
            '&lt;br /&gt;',
            '<br />'
            )

# ------------------------------------------------------------------------------
# initialised instances for use later
# ------------------------------------------------------------------------------

_formatters = {}

# ------------------------------------------------------------------------------
# our kore function
#-------------------------------------------------------------------------------

def format_exception(
    type=None, value=None, traceback=None, limit=LIMIT, as_html=False,
    with_filenames=False
    ):
    """Format a stack trace and the exception information."""

    if not type:
        type, value, traceback = sys.exc_info()

    if as_html:
        formatter = HTMLExceptionFormatter(limit, with_filenames)
    else:
        formatter = TextExceptionFormatter(limit, with_filenames)

    return formatter.formatException(type, value, traceback)

def print_exception(
    type=None, value=None, traceback=None, limit=LIMIT, as_html=False,
    with_filenames=False, stream=None
    ):
    """Print the exception to the given `stream`."""

    info = format_exception(
        type, value, traceback, limit, as_html, with_filenames
        )

    if stream is None:
        return ''.join(info)
    else:
        for line in info:
            stream.write(line)
        return ''
