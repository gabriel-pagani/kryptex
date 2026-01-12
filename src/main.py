import flet as ft
from pages.login import App


def main(page: ft.Page):
    App(page)


ft.run(main, assets_dir="assets")
