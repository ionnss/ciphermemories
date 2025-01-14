1. Setup Process:
When a user first wants to access their private memories
They create a special "memories password" that is:
Hashed and stored separately
Never recoverable (if lost, private memories become inaccessible)
Different from their login password

2. Database Changes Needed:
- done [X]

Create migrations
```sql
ALTER TABLE memories ADD COLUMN memories_password_hash VARCHAR(255);
ALTER TABLE memories ADD COLUMN has_memories_manager BOOLEAN DEFAULT FALSE;
```

3. User Flow:
```
User -> Login -> View Private Memories
                      |
                      v
               Check if has_memories_manager
                      |
            Yes ------------------- No
             |                      |
     Prompt for memories      Setup memories
         password             manager first
             |                      |
     Decrypt private         Create memories
        memories              password

```

