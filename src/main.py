import flet as ft
from views.auth import AuthView
from views.home import HomeView


class Main:
    def __init__(self, page: ft.Page):
        self.page = page
        self.setup_page()
        self.auth_view()

    def setup_page(self):
        self.page.title = 'Kryptex'
        self.page.window.icon = r'favicon.png'
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.bgcolor = ft.Colors.WHITE
        self.page.padding = 0
        self.page.window.width = 600
        self.page.window.height = 750
        self.page.update()

    def auth_view(self):
        AuthView(self.page, on_login_success=self.home_view).show_login()

    def home_view(self, user, user_key):
        HomeView(self.page, user, user_key, on_logout=self.logout).show_home()

    def logout(self, e):
        self.auth_view()


def main(page: ft.Page):
    Main(page)


ft.run(main, assets_dir="assets")
