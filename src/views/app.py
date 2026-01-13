import flet as ft
import asyncio
from controllers.user import User
from controllers.password import Password
from controllers.password_type import PasswordType
from utils.validator import validate_master_password


class App:
    def __init__(self, page: ft.Page):
        self.page = page
        self.user = None
        self.user_key = None
        self.passwords = list()
        self.password_types = list()
        self.setup_page()
        self.show_login_view()

    def setup_page(self):
        self.page.title = 'Kryptex'
        self.page.window.icon = r'favicon.png'
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.bgcolor = ft.Colors.WHITE
        self.page.padding = 0
        self.page.window.width = 600
        self.page.window.height = 750
        self.page.update()

    def show_message(self, type: int, message: str):
        if type == 1:  # Success
            snack_bar = ft.SnackBar(
                content=ft.Text(message, color=ft.Colors.WHITE),
                bgcolor=ft.Colors.GREEN
            )
        elif type == 2:  # Warning
            snack_bar = ft.SnackBar(
                content=ft.Text(message, color=ft.Colors.BLACK),
                bgcolor=ft.Colors.YELLOW
            )
        elif type == 3:  # Error
            snack_bar = ft.SnackBar(
                content=ft.Text(message, color=ft.Colors.WHITE),
                bgcolor=ft.Colors.RED
            )
        elif type == 4:  # Info
            snack_bar = ft.SnackBar(
                content=ft.Text(message, color=ft.Colors.WHITE),
                bgcolor=ft.Colors.BLUE
            )
        else:
            raise ValueError('Invalid message type')
        
        self.page.overlay.append(snack_bar)
        snack_bar.open = True
        self.page.update()

    def show_master_password_confirmation(self, e, master_password_confirmed_input):
        if e.control.value:
            master_password_confirmed_input.visible = True
        else:
            master_password_confirmed_input.visible = False
        self.page.update()

    def show_login_view(self):
        def login(e):
            username = username_input.value
            master_password = master_password_input.value

            if not username:
                self.show_message(2, 'The username field is required!')
            elif not master_password:
                self.show_message(2, 'The master password field is required!')
            else:
                user, user_key, msg_type, msg = User.login(username, master_password)
                if user:
                    self.user = user
                    self.user_key = user_key
                    self.passwords = Password.get_all_by_user(self.user.id)
                    self.password_types = PasswordType.get_all()
                    self.page.clean()
                    self.show_home_view()
                    self.show_message(msg_type, msg)

                else:
                    self.show_message(msg_type, msg)

        def register(e):
            self.page.clean()
            self.show_register_view()

        # Components
        title = ft.Text(
            "Kryptex!", 
            size=70,
            weight=ft.FontWeight.BOLD, 
            color=ft.Colors.BLUE_900
        )

        username_input = ft.TextField(
            label="Username",
            prefix_icon=ft.Icons.PERSON,
            hint_text="Enter your username here...",
            width=400,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            on_submit=login,
        )

        master_password_input = ft.TextField(
            label="Master password",
            prefix_icon=ft.Icons.LOCK,
            hint_text="Enter your master password here...",
            password=True,
            width=400,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            on_submit=login,
        )

        login_button = ft.Button(
            content="Login",
            width=400,
            height=50,
            bgcolor=ft.Colors.BLUE_900,
            color=ft.Colors.WHITE,
            on_click=login,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8)
            )
        )

        register_button = ft.Button(
            content="Create account",
            width=400,
            height=50,
            bgcolor=ft.Colors.WHITE,
            color=ft.Colors.BLUE_900,
            on_click=register,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8)
            )
        )

        # Layout
        content = ft.Column(
            controls=[
                title,
                ft.Divider(height=30, color=ft.Colors.TRANSPARENT),
                username_input,
                master_password_input,
                ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
                login_button,
                register_button
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=15
        )

        container = ft.Container(
            content=content,
            expand=True,
            alignment=ft.Alignment.CENTER
        )

        self.page.add(container)

    def show_register_view(self):
        def register(e):
            username = username_input.value
            master_password = master_password_input.value
            master_password_confirmed = master_password_confirmed_input.value

            if not username:
                self.show_message(2, 'The username field is required!')
            elif not master_password:
                self.show_message(2, 'The master password field is required!')
            elif not master_password_confirmed:
                self.show_message(2, 'The master password confirmation field is required!')
            elif master_password != master_password_confirmed:
                self.show_message(2, "The passwords don't match!")
            elif not validate_master_password(master_password):
                self.show_message(2, "Weak password! The password must contain at least 15 characters or more.")
            else:
                new_user, msg_type, msg = User.create(username, master_password)

                if new_user:
                    self.show_message(msg_type, msg)
                    self.page.clean()
                    self.show_login_view()
                
                else:
                    self.show_message(msg_type, msg)

        def login(e):
            self.page.clean()
            self.show_login_view()

        # Components
        title = ft.Text(
            "Create Account", 
            size=70, 
            weight=ft.FontWeight.BOLD, 
            color=ft.Colors.BLUE_900
        )

        username_input = ft.TextField(
            label="Username",
            prefix_icon=ft.Icons.PERSON,
            hint_text="Enter your username here...",
            width=400,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            on_submit=register,
        )

        master_password_input = ft.TextField(
            label="Master password",
            prefix_icon=ft.Icons.LOCK,
            hint_text="Enter your master password here...",
            password=True,
            width=400,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            on_change=lambda e: self.show_master_password_confirmation(e, master_password_confirmed_input),
            on_submit=register,
        )

        master_password_confirmed_input = ft.TextField(
            label="Confirm master password",
            prefix_icon=ft.Icons.LOCK,
            hint_text="Confirm your master password here...",
            password=True,
            can_reveal_password=True,
            width=400,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            visible=False,
            on_submit=register,
        )

        register_button = ft.Button(
            content="Create account",
            width=400,
            height=50,
            bgcolor=ft.Colors.BLUE_900,
            color=ft.Colors.WHITE,
            on_click=register,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8)
            )
        )

        login_button = ft.Button(
            content="I already have an account",
            width=400,
            height=50,
            bgcolor=ft.Colors.WHITE,
            color=ft.Colors.BLUE_900,
            on_click=login,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8)
            )
        )

        # Layout
        content = ft.Column(
            controls=[
                title,
                ft.Divider(height=20, color=ft.Colors.TRANSPARENT),
                username_input,
                master_password_input,
                master_password_confirmed_input,
                ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
                register_button,
                login_button
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=15
        )

        container = ft.Container(
            content=content,
            expand=True,
            alignment=ft.Alignment.CENTER
        )

        self.page.add(container)

    def show_home_view(self):
        async def copy_to_clipboard(text: str):
            await ft.Clipboard().set(text)
            self.show_message(1, "Text copied to clipboard!")

            await asyncio.sleep(15)
                
            await ft.Clipboard().set("")
            self.show_message(4, "Clean clipboard for safety!")

        def logout(e):
            self.user = None
            self.user_key = None
            self.passwords = list()
            self.password_types = list()
            self.page.clean()
            self.show_login_view()

        def placeholder(text: str) -> ft.Control:
            return ft.Container(
                content=ft.Text(
                    text,
                    size=16,
                    color=ft.Colors.GREY_700,
                    text_align=ft.TextAlign.CENTER,
                ),
                alignment=ft.Alignment.CENTER,
                expand=True,
                padding=ft.Padding.only(top=30),
            )

        def build_expansion_tiles_controls(filter: str = None) -> list[ft.Control]:
            # Filter
            if filter:
                filter = filter.lower()
                filtered_passwords = [
                    password for password in self.passwords
                    if any(
                        filter in (field or "").lower()
                        for field in (
                            password.service,
                            password.login,
                            password.url,
                            password.notes,
                        )
                    )
                ]
            else:
                filtered_passwords = self.passwords

            # Placeholder
            if not filtered_passwords:
                if filter:
                    return [placeholder(f'No results found for "{filter}"')]
                return [placeholder("You haven't saved any passwords yet!")]
            
            # Groups passwords by type
            passwords_by_type = dict()
            for type in self.password_types:
                temp_passwords_by_type = list()
                for password in filtered_passwords:
                    if password.type_id == type.id:
                        temp_passwords_by_type.append(password)
                        
                passwords_by_type[type.name] = temp_passwords_by_type

            temp_passwords_by_type = list()
            for password in filtered_passwords:
                if password.type_id is None:
                    temp_passwords_by_type.append(password)
                        
                passwords_by_type['Others'] = temp_passwords_by_type

            # Create the expansion tiles based on the password dictionary
            expansion_tiles_controls = list()
            for password_type, passwords in passwords_by_type.items():
                tile_controls = list()
                for password in passwords:
                    tile_controls.append(
                        ft.ListTile(
                            title=ft.Text(password.service),
                            subtitle=ft.Text(password.login) if password.login else None,
                        )
                    )

                if not tile_controls:
                        continue
                
                expansion_tiles_controls.append(
                    ft.ExpansionTile(
                        title=ft.Text(password_type, weight=ft.FontWeight.BOLD),
                        subtitle=ft.Text(f"{len(tile_controls)} item(s)", style=ft.TextStyle(italic=True)),
                        affinity=ft.TileAffinity.PLATFORM,
                        maintain_state=True,
                        shape=ft.RoundedRectangleBorder(
                            side=ft.BorderSide(color=ft.Colors.TRANSPARENT, width=0)
                        ),
                        collapsed_shape=ft.RoundedRectangleBorder(
                            side=ft.BorderSide(color=ft.Colors.TRANSPARENT, width=0)
                        ),
                        controls=tile_controls,
                    )
                )
            
            return expansion_tiles_controls

        def search(e):
            tiles_list.controls = build_expansion_tiles_controls(e.control.value)
            self.page.update()

        # Components
        popup_menu = ft.PopupMenuButton(
            items=[
                ft.PopupMenuItem(
                    content=ft.Row(
                        [
                            ft.Icon(ft.Icons.PERSON, ft.Colors.BLACK),
                            ft.Text("My account"),
                        ]
                    ),
                    on_click=...,
                ),
                ft.PopupMenuItem(
                    content=ft.Row(
                        [
                            ft.Icon(ft.Icons.ADD, ft.Colors.BLACK),
                            ft.Text("New password"),
                        ]
                    ),
                    on_click=...,
                ),                
                ft.PopupMenuItem(
                    content=ft.Row(
                        [
                            ft.Icon(ft.Icons.LOGOUT, ft.Colors.BLACK),
                            ft.Text("Logout"),
                        ]
                    ),
                    on_click=logout,
                ),
            ],
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

        search_input = ft.TextField(
            hint_text="Search here for services, logins, URLs and notes...",
            prefix_icon=ft.Icons.SEARCH,
            border_color=ft.Colors.BLUE_400,
            cursor_color=ft.Colors.BLUE_900,
            expand=True,
            on_change=search,
        )

        tiles_list = ft.ListView(
            expand=True,
            spacing=6,
            padding=ft.Padding.only(left=12, right=12, top=8, bottom=12),
            controls=build_expansion_tiles_controls(),
        )

        # Layout
        content = ft.Column(
            controls=[
                top_bar,
                ft.Container(search_input, padding=ft.Padding.only(left=12, right=12, top=10, bottom=4)),
                tiles_list,
            ],
            spacing=4,
            expand=True,
        )

        self.page.add(content)
