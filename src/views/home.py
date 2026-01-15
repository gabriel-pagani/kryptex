import flet as ft
import shutil
from utils.ui import show_message
from database.connection import DB_PATH


class HomeView:
    def __init__(self, page: ft.Page, user, user_key, on_logout):
        self.page = page
        self.user = user
        self.user_key = user_key
        self.on_logout = on_logout

    def show_home(self):
        async def export_database(e):
            file_picker = ft.FilePicker()
            path = await file_picker.save_file(file_name='db.sqlite3', file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=['sqlite3'])
            
            if path:
                try:
                    shutil.copy(DB_PATH, path)
                    show_message(self.page, 1, "Database exported successfully!")
                except Exception as ex:
                    show_message(self.page, 3, "Error exporting database! Please try again later.")
        
        # Components
        menu_items = [
            ft.PopupMenuItem(
                content=ft.Row([ft.Icon(ft.Icons.PERSON, ft.Colors.BLACK), ft.Text("My account"),]),
                on_click=lambda e: show_message(self.page, 4, "Coming soon"),
            )
        ]

        if self.user.is_admin:
            menu_items.extend(
                [
                    ft.PopupMenuItem(
                        content=ft.Row(
                            [ft.Icon(ft.Icons.UPLOAD, ft.Colors.BLACK), ft.Text("Import passwords"),]
                        ),
                        # on_click=import_database, 
                    ),
                    ft.PopupMenuItem(
                        content=ft.Row([ft.Icon(ft.Icons.DOWNLOAD, ft.Colors.BLACK), ft.Text("Export passwords"),]),
                        on_click=export_database,
                    ),
                ]
            )

        menu_items.extend(
            [
                ft.PopupMenuItem(
                    content=ft.Row([ft.Icon(ft.Icons.ADD, ft.Colors.BLACK), ft.Text("New password"),]),
                    # on_click=open_new_password_dialog, 
                ),                
                ft.PopupMenuItem(
                    content=ft.Row([ft.Icon(ft.Icons.LOGOUT, ft.Colors.BLACK), ft.Text("Logout"),]),
                    on_click=self.on_logout,
                ),
            ]
        )

        popup_menu = ft.PopupMenuButton(
            items=menu_items,
            icon_color=ft.Colors.WHITE,
            icon_size=30,
        )

        top_bar = ft.AppBar(
            toolbar_height=80,
            title=ft.Container(
                content=ft.Text(
                    "Kryptex",
                    size=30,
                    weight=ft.FontWeight.W_500,
                ),
                padding=ft.Padding.only(left=16),
            ),
            center_title=False,
            color=ft.Colors.WHITE,
            bgcolor=ft.Colors.BLUE_900,
            actions=[
                ft.Container(popup_menu, padding=ft.Padding.only(right=16)),
            ],
        )

        tiles_list = ft.ListView(
            expand=True,
            spacing=6,
            padding=ft.Padding.only(left=12, right=12, top=8, bottom=12),
        )

        # Layout
        content = ft.Column(
            controls=[
                top_bar,
                tiles_list,
            ],
            spacing=4,
            expand=True,
        )

        self.page.clean()       
        self.page.add(content)
