import flet as ft
from pages.login import Login


def main(page: ft.Page):
    Login(page)


ft.run(main, assets_dir="assets")
