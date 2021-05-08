class Project:

    def __init__(self, project_name: str = None, project_id: str = None) -> None:
        self.project_name = project_name
        self.project_id = project_id

    def __repr__(self):
        return repr((self.project_name, self.project_id))

    def __eq__(self, other):
        return self.project_name == other.project_name and self.project_id == other.project_id
