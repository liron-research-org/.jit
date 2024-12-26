from django.shortcuts import render
from django.shortcuts import render_to_response
from django.utils.html import escape

class FalsePositiveCheck499View(VulnerableTemplateView):
    title = '(almost) Cross-Site Scripting'
    tags = ['false-positive', 'GET', 'filtered']
    description = 'Echo query string parameter to HTML tag attribute removing'\
                  ' the single quotes which are present in the input.'
    url_path = '499_check.py?text=1'
    false_positive_check = True
    references = ['https://github.com/andresriancho/w3af/pull/499']

    def get(self, request, *args, **kwds):
        context = self.get_context_data() 

        text = request.GET['text']
        text = text.replace('"', '')

        link = '<a href="http://external/abc/%s">Check link href</a>'

        # ruleid: raw-html-format
        context['html'] = link % text

        return render(request, self.template_name, context)

    def getB(self, request, *args, **kwds):
        context = self.get_context_data()

        text = request.GET['text']
        text = text.replace('"', '')

        # ruleid: raw-html-format
        context['html'] = '<a href="http://external/abc/' + text + '">Check link href</a>'

        return render(request, self.template_name, context)

    def get2(self, request, *args, **kwds):
        context = self.get_context_data()

        text = request.GET['text']
        text = text.replace('"', '')

        link = '<a href="http://external/abc/{}">Check link href</a>'

        # ruleid: raw-html-format
        context['html'] = link.format(text)

        return render(request, self.template_name, context)

    def get3(self, request, *args, **kwds):
        context = self.get_context_data()

        text = request.GET['text']
        text = text.replace('"', '')

        # ruleid: raw-html-format
        context['html'] = '<a href="http://external/abc/%s">Check link href</a>' % text

        return render(request, self.template_name, context)

    def get4(self, request, *args, **kwds):
        context = self.get_context_data()

        text = request.GET['text']
        text = text.replace('"', '')

        # ruleid: raw-html-format
        context['html'] = '<a href="http://external/abc/%s">Check link href</a>'.format(text)

        return render(request, self.template_name, context)

    def get5(self, request, *args, **kwds):
        context = self.get_context_data()

        text = request.GET['text']
        text = text.replace('"', '')

        # ruleid: raw-html-format
        context['html'] = f'<a href="http://external/abc/{text}">Check link href</a>'

        return render(request, self.template_name, context)

    def ok(self, request, *args, **kwds):
        context = self.get_context_data()

        text = request.GET['text']
        text = text.replace('"', '')

        link = 'something other than html, %s!'

        # ok: raw-html-format
        context['html'] = link % text

        return render(request, self.template_name, context)

    def ok2(self, request, *args, **kwds):
        context = self.get_context_data()

        text = request.GET['text']
        text = text.replace('"', '')

        # ok: raw-html-format
        context['html'] = 'this is a random string. {}'.format(text)

        return render(request, self.template_name, context)

    def ok3(self, request):
        # ok: raw-html-format
        msg += ' (<a href="{}" target="_blank" rel="noopener">{}</a>)'.format(
            request.build_absolute_uri(reverse('source')),
            gettext('source code')
        )

    def ok4(self, request):
        form = CreateQuestionForm(request.POST)
        if '_popup' in request.GET and not error:
            # ok: raw-html-format
            resp = '<script type="text/javascript">opener.dismissAddAnotherPopupDojo(window, "%s", "%s");</script>' \
                % (escape(form.cleaned_data['something']), escape(form.cleaned_data['text']))
            resp += '<script type="text/javascript">window.close();</script>'
            return HttpResponse(resp)

      # cf. https://github.com/returntocorp/semgrep/blob/develop/docs/writing_rules/examples.md#auditing-dangerous-function-use-tainted-env-args

import subprocess
import sys


def ok():
    # ok:dangerous-subprocess-use-tainted-env-args
    subprocess.call("echo 'hello'")

    # ok:dangerous-subprocess-use-tainted-env-args
    subprocess.call(["echo", "a", ";", "rm", "-rf", "/"])

    # ok:dangerous-subprocess-use-tainted-env-args
    subprocess.call(("echo", "a", ";", "rm", "-rf", "/"))

    # ok:dangerous-subprocess-use-tainted-env-args
    raise subprocess.CalledProcessError("{}".format("foo"))

    # ok:dangerous-subprocess-use-tainted-env-args
    raise subprocess.SubprocessError("{}".format("foo"))


def bad1():
    cmd = sys.argv[1]
    # ruleid:dangerous-subprocess-use-tainted-env-args
    subprocess.call(cmd)


def bad2():
    # ruleid:dangerous-subprocess-use-tainted-env-args
    subprocess.call("grep -R {} .".format(sys.argv[1]))


def bad3():
    # ruleid:dangerous-subprocess-use-tainted-env-args
    subprocess.call("grep -R {} .".format(sys.argv[1]), shell=True)


def bad4():
    # ruleid:dangerous-subprocess-use-tainted-env-args
    subprocess.call("grep -R {} .".format(sys.argv[1]), shell=True, cwd="/home/user")


def bad5():
    # ruleid:dangerous-subprocess-use-tainted-env-args
    subprocess.run("grep -R {} .".format(sys.argv[1]), shell=True)


def bad6():
    # ruleid:dangerous-subprocess-use-tainted-env-args
    subprocess.run(["bash", "-c", sys.argv[1]], shell=True)


def bad7():
    cmd = sys.argv[1]
    # ruleid:dangerous-subprocess-use-tainted-env-args
    subprocess.call([cmd[0], cmd[1], "some", "args"])


def fn1(user_input):
    cmd = user_input.split()
    # fn:dangerous-subprocess-use-tainted-env-args
    subprocess.call([cmd[0], cmd[1], "some", "args"])


def fn2(payload: str) -> None:
    with tempfile.TemporaryDirectory() as directory:
        python_file = Path(directory) / "hello_world.py"
        python_file.write_text(
            textwrap.dedent(
                """
        print("What is your name?")
        name = input()
        print("Hello " + name)
    """
            )
        )
        # fn:dangerous-subprocess-use-tainted-env-args
        program = subprocess.Popen(
            ["python2", str(python_file)], stdin=subprocess.PIPE, text=True
        )
        program.communicate(input=payload, timeout=1)
