import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ ok: false, error: "Método não permitido." }, 405);

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !serviceRoleKey) {
      return json({ ok: false, error: "Variáveis do Supabase não configuradas na Edge Function." }, 500);
    }

    const body = await req.json();
    const nome = String(body?.nome ?? "").trim();
    const password = String(body?.password ?? "");
    const senhaEspecial = String(body?.senhaEspecial ?? "");

    if (!nome || !password || !senhaEspecial) {
      return json({ ok: false, error: "Informe nome, senha e senha especial." }, 400);
    }
    if (nome.length < 2 || nome.length > 80) {
      return json({ ok: false, error: "O nome deve ter entre 2 e 80 caracteres." }, 400);
    }
    if (password.length < 6) {
      return json({ ok: false, error: "A senha precisa ter pelo menos 6 caracteres." }, 400);
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    // A senha especial continua sendo validada no banco.
    const { data: valid, error: validError } = await admin.rpc("validar_senha_cadastro", {
      p_senha: senhaEspecial,
    });

    if (validError) {
      return json({ ok: false, error: "Não foi possível validar a senha especial." }, 500);
    }
    if (!valid) {
      return json({ ok: false, error: "Senha especial de acesso incorreta." }, 403);
    }

    // O Auth ainda precisa de um identificador. Ele é interno, não é um
    // endereço de e-mail real e nunca é exibido ao usuário.
    const normalized = nome
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .trim();
    const slug = normalized.replace(/[^a-z0-9]+/g, ".").replace(/^\.+|\.+$/g, "").slice(0, 50) || "usuario";
    let hash = 0;
    for (let i = 0; i < normalized.length; i++) hash = ((hash << 5) - hash + normalized.charCodeAt(i)) | 0;
    const hashText = Math.abs(hash).toString(36);
    const email = `u.${slug}.${hashText}@local.invalid`;

    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { nome },
    });

    if (createError) {
      if (/already registered|already been registered|already exists/i.test(createError.message)) {
        return json({ ok: false, error: "Esse nome já possui uma conta." }, 409);
      }
      return json({ ok: false, error: createError.message }, 400);
    }

    return json({ ok: true, email, userId: created.user?.id ?? null });
  } catch (error) {
    console.error(error);
    return json({ ok: false, error: "Erro interno ao criar a conta." }, 500);
  }
});
