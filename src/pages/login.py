import flet as ft
from controllers.user import User


class Login:
    def __init__(self, page: ft.Page):
        self.page = page
        self.user = None
        self.user_key = None
        self.setup_page()

    def setup_page(self):
        self.page.title = 'Kryptex'
        self.page.window.icon = r''
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.bgcolor = ft.Colors.GREY
        self.page.padding = 0
        self.page.update()

    def show_message(self, type: int, message: str):
        if type == 1:  # Success
            snack_bar = ft.SnackBar(
                content=ft.Text(message, color=ft.Colors.WHITE),
                bgcolor=ft.Colors.GREEN_600
            )
        elif type == 2:  # Warning
            snack_bar = ft.SnackBar(
                content=ft.Text(message, color=ft.Colors.BLACK),
                bgcolor=ft.Colors.AMBER_400
            )
        elif type == 3:  # Error
            snack_bar = ft.SnackBar(
                content=ft.Text(message, color=ft.Colors.WHITE),
                bgcolor=ft.Colors.RED_600
            )
        else:
            raise ValueError('Invalid message type')
        
        self.page.overlay.append(snack_bar)
        snack_bar.open = True
        self.page.update()
