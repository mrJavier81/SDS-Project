// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister    = "register"
	ActionLogin       = "login"
	ActionFetchData   = "fetchData"
	ActionUpdateData  = "updateData"
	ActionLogout      = "logout"
	ActionManageUsers = "manageUsers"
	ActionCreatePoll  = "createPoll"
	ActionVote        = "vote"
	ActionFetchPolls  = "fetchPolls"
	ActionDeletePoll  = "deletePoll"
	ActionModifyPoll  = "modifyPoll"
)

// Request y Response como antes
type Request struct {
	Action   string   `json:"action"`
	Username string   `json:"username"`
	Password string   `json:"password,omitempty"`
	Token    string   `json:"token,omitempty"`
	Data     string   `json:"data,omitempty"`
	Role     string   `json:"role,omitempty"`
	NewRole  string   `json:"newRole,omitempty"`
	PollID   string   `json:"poll_id,omitempty"`  // ID de la votacion
	Question string   `json:"question,omitempty"` // Pregunta de la votacion
	Options  []string `json:"options,omitempty"`  // Opciones de la votacion
	Option   string   `json:"option,omitempty"`
	Creador  string   `json:"creator,omitempty"` // Creador de la votacion
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	Data    string `json:"data,omitempty"`
}
