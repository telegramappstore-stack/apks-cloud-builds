"""Entry point. If anything goes wrong at startup, show the error on screen instead of silently closing."""
import os
import traceback


def show_error(err):
    try:
        with open(os.path.join(os.path.expanduser("~"), "proxychecker_error.txt"), "w") as f:
            f.write(err)
    except Exception:
        pass
    from kivy.app import App
    from kivy.core.clipboard import Clipboard
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.button import Button
    from kivy.uix.textinput import TextInput

    class ErrApp(App):
        def build(self):
            root = BoxLayout(orientation="vertical")
            root.add_widget(TextInput(text=err, readonly=True, font_size="12sp"))
            b = Button(text="Copy error text", size_hint_y=None, height=140)
            b.bind(on_release=lambda *_: Clipboard.copy(err))
            root.add_widget(b)
            return root

    ErrApp().run()


try:
    from proxyapp import ProxyApp
    ProxyApp().run()
except Exception:
    show_error(traceback.format_exc())
