import flet as ft


def show_message(page: ft.Page, type: int, message: str):
    colors = {
        1: [ft.Colors.GREEN, ft.Colors.WHITE],  # Success
        2: [ft.Colors.YELLOW, ft.Colors.BLACK], # Warning
        3: [ft.Colors.RED, ft.Colors.WHITE],    # Error
        4: [ft.Colors.GREY, ft.Colors.BLACK],   # Info
    }

    page.overlay.append(
        ft.SnackBar(
            content=ft.Text(message, color=colors[type][1]),
            bgcolor=colors[type][0],
            open=True
        )
    )

    page.update()
