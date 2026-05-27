package server

import (
	"context"
	"sort"
)

type ToolHandler func(context.Context, *Env, map[string]any) (any, error)

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Risk        string         `json:"-"`
	Handler     ToolHandler    `json:"-"`
}

type Registry struct{ tools map[string]Tool }

func NewRegistry() *Registry { return &Registry{tools: map[string]Tool{}} }

func (r *Registry) Register(t Tool) {
	if t.InputSchema == nil {
		t.InputSchema = ObjectSchema(nil, nil)
	}
	r.tools[t.Name] = t
}

func (r *Registry) Get(name string) (Tool, bool) { t, ok := r.tools[name]; return t, ok }

func (r *Registry) List() []Tool {
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func ObjectSchema(props map[string]any, required []string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func StringProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func BoolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func NumberProp(desc string) map[string]any {
	return map[string]any{"type": "number", "description": desc}
}
func IntProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func StringArrayProp(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}
