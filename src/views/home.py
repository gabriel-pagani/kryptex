import flet as ft
import shutil
from utils.ui import show_message
from utils.cryptor import generate_password
from database.connection import DB_PATH
from controllers.password import Password


class HomeView:
    def __init__(self, page: ft.Page, user, user_key, on_logout):
        self.page = page
        self.user = user
        self.user_key = user_key
        self.on_logout = on_logout

    def show_home(self):
        # Dialogs components
        service_input = ft.TextField(
            label="Service", 
            prefix_icon=ft.Icons.PUBLIC,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            width=400,
        )
        
        login_input = ft.TextField(
            label="Login/Username", 
            prefix_icon=ft.Icons.PERSON,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            width=400,
        )
        
        password_input = ft.TextField(
            label="Password", 
            password=True, 
            can_reveal_password=True, 
            prefix_icon=ft.Icons.KEY,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            width=350,
        )

        def generate_random_password(e):
            password_input.value = generate_password()
            password_input.update()

        generate_password_button = ft.IconButton(
            icon=ft.Icons.AUTO_AWESOME,
            tooltip="Generate random password",
            on_click=generate_random_password
        )

        type_dropdown = ft.Dropdown(
            label="Type",
            border_color=ft.Colors.BLUE_400,
            focused_border_color=ft.Colors.BLUE_900,
            width=400,
            options=[
                *(ft.dropdown.Option(key=str(t.id), text=t.name) for t in self.password_types),
                ft.dropdown.Option(key="", text="Others"),
            ],
            key="",
            text="Others",
            leading_icon=ft.Icons.CATEGORY,
        )

        url_input = ft.TextField(
            label="URL", 
            prefix_icon=ft.Icons.LINK,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            width=400,
        )
        
        notes_input = ft.TextField(
            label="Notes", 
            multiline=True, 
            min_lines=3,
            max_lines=3,
            prefix_icon=ft.Icons.CREATE,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            width=400,
        )

        # Dialogs
        def close_dialog(e):
            ...       
        
        def open_new_password_dialog(e):
            ...

        def save_new_password(e):
            ...        
        
        new_password_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("New password"),
            content=ft.Column(
                controls=[
                    service_input,
                    login_input,
                    ft.Row(
                        controls=[password_input, generate_password_button], 
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=10,
                    ),
                    type_dropdown,
                    url_input,
                    notes_input
                ],
                expand=True,
                scroll=ft.ScrollMode.AUTO,
                height=450,
                alignment=ft.MainAxisAlignment.START,
                spacing=10
            ),
            actions=[
                ft.TextButton("Cancel", on_click=close_dialog),
                ft.TextButton("Save", on_click=save_new_password),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )


        editing_password: Password | None = None
        def open_edit_password_dialog(e, password: Password):
            ...
        
        def save_edited_password(e, password: Password):
            ...

        def confirm_delete_password(e):
            ...

        def delete_password(e, password: Password):
            ...

        edit_password_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Edit password"),
            content=ft.Column(
                controls=[
                    service_input,
                    login_input,
                    ft.Row(
                        controls=[password_input, generate_password_button], 
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=10,
                    ),
                    type_dropdown,
                    url_input,
                    notes_input
                ],
                expand=True,
                scroll=ft.ScrollMode.AUTO,
                height=450,
                alignment=ft.MainAxisAlignment.START,
                spacing=10
            ),
            actions=[
                ft.TextButton("Delete", on_click=lambda e: delete_password(e, editing_password)),
                ft.TextButton("Cancel", on_click=close_dialog),
                ft.TextButton("Save", on_click=lambda e: save_edited_password(e, editing_password)),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

        # Page components
        menu_items = [
            ft.PopupMenuItem(
                content=ft.Row([ft.Icon(ft.Icons.PERSON, ft.Colors.BLACK), ft.Text("My account"),]),
                on_click=lambda e: show_message(self.page, 4, "Coming soon"),
            )
        ]

        if self.user.is_admin:
            async def export_database(e):
                file_picker = ft.FilePicker()
                path = await file_picker.save_file(file_name='db.sqlite3', file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=['sqlite3'])
                
                if path:
                    try:
                        shutil.copy(DB_PATH, path)
                        show_message(self.page, 1, "Database exported successfully!")
                    except Exception as ex:
                        show_message(self.page, 3, "Error exporting database! Please try again later.")
            
            def confirm_import_database(e, import_path):
                try:
                    shutil.copy(import_path, DB_PATH)
                    show_message(self.page, 1, "Database imported successfully!")
                    self.page.pop_dialog()
                    self.on_logout(e)
                except Exception:
                    show_message(self.page, 3, "Error importing database! Please try again later.")

            async def import_database(e):
                file = await ft.FilePicker().pick_files(file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=["sqlite3"], allow_multiple=False)
                
                import_confirmation_dialog = ft.AlertDialog(
                    modal=True,
                    title=ft.Text("Confirm import"),
                    content=ft.Text("Importing a new database will overwrite all your current data. This action cannot be undone. Are you sure?"),
                    actions=[
                        ft.TextButton("No", on_click=lambda e: self.page.pop_dialog()),
                        ft.TextButton("Yes", on_click=lambda e: confirm_import_database(e, file[0].path)),
                    ],
                    actions_alignment=ft.MainAxisAlignment.END,
                )
                
                if file:
                    self.page.show_dialog(import_confirmation_dialog)
            
            menu_items.extend(
                [
                    ft.PopupMenuItem(
                        content=ft.Row(
                            [ft.Icon(ft.Icons.UPLOAD, ft.Colors.BLACK), ft.Text("Import passwords"),]
                        ),
                        on_click=import_database,
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
                    on_click=open_new_password_dialog,
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
